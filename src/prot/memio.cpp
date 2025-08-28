#include "memio.h"
#include "netio.h"
#include "misc/defer.h"
#include "misc/hook.h"
#include <inttypes.h>

MemRWer::MemRWer(const Destination& src, const Destination& dst, std::shared_ptr<IMemRWerCallback> cb):
    FullRWer(IRWerCallback::create()->onError([](int, int){})), _callback(std::move(cb))
{
    memcpy(&this->src, &src, sizeof(Destination));
    memcpy(&this->dst, &dst, sizeof(Destination));
}

MemRWer::~MemRWer() {
}

size_t MemRWer::rlength(uint64_t) {
    return rb.length();
}

ssize_t MemRWer::cap(uint64_t) {
    if(auto cb = _callback.lock(); cb) {
        return std::min(cb->cap_cb() - wbuff.length(), wbuff.cap());
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
    HOOK_FUNC(this, rb, bb);
    assert(stats != RWerStats::ReadEOF);
    LOGD(DRWER, "<MemRWer> <%d> %s push_data [%" PRIu64"]: %zd, refs: %zd\n",
         getFd(), dumpDest(src).c_str(), bb.id, bb.len, bb.refs());
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        rb.put(std::move(bb));
    }
    addEvents(RW_EVENT::READ);
}

void MemRWer::push_signal(Signal s) {
    LOGD(DRWER, "<MemRWer> <%d> %s push_signal: %d, cb: %ld\n",
         getFd(), dumpDest(src).c_str(), (int)s, callback.use_count());
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
        keepReading = true;
        while(rb.length() > 0){
            Buffer wb = rb.get();
            assert(wb.len != 0);
            wb.id = id;
            auto ret = cb->readCB(std::move(wb));
            if(ret > 0) {
                rb.consume(ret);
                continue;
            }
            keepReading = false;
            break;
        }
    }
    HOOK_FUNC(this, rb, id);
    if(rb.length() == 0 && isEof() && (flags & RWER_EOFDELIVED) == 0){
        keepReading = false;
        if(auto cb = callback.lock(); cb) {
            cb->readCB({nullptr, id});
            flags |= RWER_EOFDELIVED;
        }
    }
    if(!keepReading){
        delEvents(RW_EVENT::READ);
    }
}

ssize_t MemRWer::Write(std::set<uint64_t>& writed_list) {
    if(_callback.expired()){
        size_t wlen = wbuff.length();
        if(wlen) LOGE("MemRWer <%d> %s callback expired, left: %zd\n", getFd(), dumpDest(src).c_str(), wlen);
        delEvents(RW_EVENT::WRITE);
        errno = EPIPE;
        return -1;
    }
    size_t len = 0;
    auto& write_cb = _callback.lock()->write_data;
    while(!wbuff.empty()){
        auto bb = wbuff.get();
        size_t blen = bb.len;
        ssize_t ret = write_cb(std::move(bb));
        if (blen) {
            LOGD(DRWER, "<MemRWer> <%d> %s write_cb %d wlen: %zd, len: %zd, ret: %zd\n",
                 getFd(), dumpDest(src).c_str(), (int)bb.id, wbuff.length(), blen, ret);
        } else {
            assert(flags & RWER_SHUTDOWN);
            LOGD(DRWER, "<MemRWer> <%d> %s write_cb %d EOF, wlen: %zd\n",
                 getFd(), dumpDest(src).c_str(), (int)bb.id, wbuff.length());
        }
        if(ret < 0 || (blen > 0 && ret == 0)){
            delEvents(RW_EVENT::WRITE);
            return ret;
        }
        writed_list.emplace(bb.id);
        wbuff.consume(ret);
        len += ret;
    }
    return (ssize_t)len;
}

void MemRWer::closeHE(RW_EVENT) {
    if((flags & RWER_SHUTDOWN) == 0 && (stats == RWerStats::ReadEOF || stats == RWerStats::Connected)){
        flags |= RWER_SHUTDOWN;
        wbuff.put({nullptr});
    }
    std::set<uint64_t> writed_list;
    ssize_t ret = Write(writed_list);
    if (wbuff.empty() || (ret <= 0 && errno != EAGAIN && errno != ENOBUFS)) {
        handleEvent = (void(Ep::*)(RW_EVENT))&MemRWer::IdleHE;
        setEvents(RW_EVENT::NONE);
        if(auto cb = _callback.lock(); cb) {
            cb->write_signal(CHANNEL_ABORT);
        }
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    }
}

void MemRWer::dump_status(Dumper dp, void* param) {
    dp(param, "MemRWer <%d> (%s): rlen: %zu, wlen: %zu, stats: %d, flags: 0x%04x, event: %s, cb: %ld, _cb: %ld\n",
        getFd(), dumpDest(src).c_str(), rlength(0), wbuff.length(),
        (int)stats, flags, events_string[(int)getEvents()], callback.use_count(), _callback.use_count());
}


void PMemRWer::push_data(Buffer&& bb) {
    HOOK_FUNC(this, rb, bb);
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});

    assert(stats != RWerStats::ReadEOF);
    LOGD(DRWER, "<PMemRWer> <%d> %s push_data [%" PRIu64"]: %zd, refs: %zd, cb: %ld\n",
         getFd(), dumpDest(src).c_str(), bb.id, bb.len, bb.refs(), callback.use_count());
    if(flags & RWER_CLOSING){
        return;
    }
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
        if(auto cb = callback.lock(); cb) {
            cb->readCB({nullptr, bb.id});
            flags |= RWER_EOFDELIVED;
        }
    } else if(auto cb = callback.lock(); cb) {
        cb->readCB(std::move(bb));
    } else {
        rb.emplace_back(std::move(bb));
    }
}


void PMemRWer::ConsumeRData(uint64_t) {
    delEvents(RW_EVENT::READ);
    auto cb = callback.lock();
    if (cb == nullptr) {
        return;
    }
    while(!rb.empty()) {
        auto bb = std::move(rb.front());
        rb.pop_front();
        cb->readCB(std::move(bb));
    }
}

void PMemRWer::Send(Buffer&& bb) {
    assert((flags & RWER_SHUTDOWN) == 0);
    if(bb.len == 0){
        flags |= RWER_SHUTDOWN;
    }
    LOGD(DRWER, "<PMemRWer> <%d> %s Send [%" PRIu64"]: %zd, refs: %zd, _cb: %ld\n",
        getFd(), dumpDest(src).c_str(), bb.id, bb.len, bb.refs(), _callback.use_count());
    if(auto _cb = _callback.lock(); _cb){
        _cb->write_data(std::move(bb));
    }
}
