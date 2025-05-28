#include "memio.h"
#include "netio.h"
#include "misc/defer.h"
#include "misc/hook.h"
#include <inttypes.h>

MemRWer::MemRWer(const Destination& src, std::shared_ptr<IMemRWerCallback> cb):
    FullRWer(IRWerCallback::create()->onError([](int, int){})), _callback(std::move(cb))
{
    memcpy(&this->src, &src, sizeof(Destination));
}

MemRWer::~MemRWer() {
}

size_t MemRWer::rlength(uint64_t) {
    return rb.length();
}

ssize_t MemRWer::cap(uint64_t) {
    if(auto cb = _callback.lock(); cb) {
        return cb->cap_cb() - wlen;
    }
    return 0;
}

void MemRWer::SetCallback(std::shared_ptr<IRWerCallback> cb) {
    RWer::SetCallback(std::move(cb));
    if(auto sockcb = std::dynamic_pointer_cast<ISocketCallback>(callback.lock()); sockcb && IsConnected()) {
        sockcb->connectCB({}, 0);
    }
}

void MemRWer::connected(const sockaddr_storage& addr) {
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&MemRWer::defaultHE;
    if(auto cb = std::dynamic_pointer_cast<ISocketCallback>(callback.lock()); cb) {
        cb->connectCB(addr, 0);
    }
}

void MemRWer::push_data(Buffer&& bb) {
    assert(stats != RWerStats::ReadEOF);
    LOGD(DRWER, "<MemRWer> push_data [%" PRIu32"]: %zd, id:%" PRIu64", refs: %zd\n",
         flags, bb.len, bb.id, bb.refs());
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        rb.put(bb.data(), bb.len);
    }
    HOOK_FUNC(this, rb, bb);
    addEvents(RW_EVENT::READ);
}

void MemRWer::push_signal(Signal s) {
    if (flags & RWER_CLOSING){
        return;
    }
    ConsumeRData(0);
    switch(s){
    case CHANNEL_ABORT:
        if(auto cb = callback.lock(); cb) {
            return cb->errorCB(PROTOCOL_ERR, PEER_LOST_ERR);
        }
    }
}

#if 0
void MemRWer::detach() {
    write_cb = [](std::variant<std::reference_wrapper<Buffer>, Buffer, Signal> data) -> int{
        if(auto bb = std::get_if<Buffer>(&data)) {
            return (int)bb->len;
        }
        if(auto bb = std::get_if<std::reference_wrapper<Buffer>>(&data)) {
            return (int)bb->get().len;
        }
        return 0;
    };
    read_cb = [](uint64_t){};
    cap_cb = []{return 0;};
}
#endif


void MemRWer::ConsumeRData(uint64_t id) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    bool keepReading = false;
    if(auto cb = callback.lock(); cb && rb.length()){
        Buffer wb = rb.get();
        assert(wb.len != 0);
        wb.id = id;
        auto ret = cb->readCB(std::move(wb));
        if(ret > 0) {
            rb.consume(ret);
            keepReading = true;
        }
    }
    HOOK_FUNC(this, rb, id);
    if(rb.length() == 0 && isEof() && (flags & RWER_EOFDELIVED) == 0){
        keepReading = false;
        if(auto cb = callback.lock(); cb) {
            cb->readCB({nullptr, id});
        }
        flags |= RWER_EOFDELIVED;
    }
    if(!keepReading){
        delEvents(RW_EVENT::READ);
    }
}

ssize_t MemRWer::Write(std::set<uint64_t>& writed_list) {
    size_t len = 0;
    if(_callback.expired()){
        LOGE("MemRWer callback expired, cannot write\n");
        return -1;
    }
    auto& write_cb = _callback.lock()->write_cb;
    for(auto it = wbuff.begin(); it != wbuff.end(); ){
        ssize_t ret = 0;
        size_t blen = it->len;
        if (blen) {
            ret = write_cb(std::ref(*it));
            LOGD(DRWER, "write_cb %d: len: %zd, ret: %zd\n", (int)it->id, blen, ret);
        } else {
            assert(flags & RWER_SHUTDOWN);
            ret = write_cb(Buffer{nullptr, it->id});
            LOGD(DRWER, "write_cb %d EOF\n", (int)it->id);
        }
        if(ret < 0){
            delEvents(RW_EVENT::WRITE);
            return ret;
        }
        writed_list.emplace(it->id);
        len += ret;
        wlen -= ret;
        if((size_t)ret == blen) {
            it = wbuff.erase(it);
        } else {
            assert(ret < (int)blen);
            it->reserve(ret);
            break;
        }
    }
    return (ssize_t)len;
}

void MemRWer::closeHE(RW_EVENT) {
    if((flags & RWER_SHUTDOWN) == 0 && (stats == RWerStats::ReadEOF || stats == RWerStats::Connected)){
        flags |= RWER_SHUTDOWN;
        wbuff.emplace_back(nullptr);
    }
    std::set<uint64_t> writed_list;
    ssize_t ret = Write(writed_list);
    if (wbuff.empty() || (ret <= 0 && errno != EAGAIN && errno != ENOBUFS)) {
        handleEvent = (void(Ep::*)(RW_EVENT))&MemRWer::IdleHE;
        setEvents(RW_EVENT::NONE);
        if(auto cb = _callback.lock(); cb) {
            cb->write_cb(CHANNEL_ABORT);
        }
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    }
}

void MemRWer::dump_status(Dumper dp, void* param) {
    dp(param, "MemRWer <%d> (%s): rlen: %zu, wlen: %zu, stats: %d, flags: 0x%04x,  event: %s\n",
        getFd(), dumpDest(src).c_str(), rlength(0), wlen,
        (int)getStats(), flags, events_string[(int)getEvents()]);
}


void PMemRWer::push_data(Buffer&& bb) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});

    assert(stats != RWerStats::ReadEOF);
    LOGD(DRWER, "<PMemRWer> push_data [%" PRIu32"]: %zd, id:%" PRIu64", refs: %zd\n",
         flags, bb.len, bb.id, bb.refs());
    if(flags & RWER_CLOSING){
        return;
    }
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
        if(auto cb = callback.lock(); cb) {
            cb->readCB({nullptr, bb.id});
        }
        flags |= RWER_EOFDELIVED;
    } else if(auto cb = callback.lock(); cb) {
        cb->readCB(std::move(bb));
    }
}

void PMemRWer::ConsumeRData(uint64_t) {
    delEvents(RW_EVENT::READ);
}
