#include "memio.h"
#include "misc/defer.h"
#include <inttypes.h>

MemRWer::MemRWer(const Destination& src,
                 std::function<int(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal>)> write_cb,
                 std::function<void(uint64_t)> read_cb,
                 std::function<ssize_t()> cap_cb):
    FullRWer([](int, int){}), write_cb(std::move(write_cb)), read_cb(std::move(read_cb)), cap_cb(std::move(cap_cb))
{
    memcpy(&this->src, &src, sizeof(Destination));
}

MemRWer::~MemRWer() {
}

size_t MemRWer::rlength(uint64_t) {
    return rb.length();
}

ssize_t MemRWer::cap(uint64_t) {
    return cap_cb() - wlen;
}

void MemRWer::SetConnectCB(std::function<void (const sockaddr_storage &)> cb){
    if(IsConnected()) {
        cb({});
    } else {
        connectCB = std::move(cb);
    }
}

void MemRWer::ErrorHE(int ret, int code) {
    if(stats != RWerStats::Error) {
        write_cb(CHANNEL_ABORT);
    }
    FullRWer::ErrorHE(ret, code);
}

void MemRWer::connected(const sockaddr_storage& addr) {
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&MemRWer::defaultHE;
    connectCB(addr);
    connectCB = [](const sockaddr_storage&){};
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
    addEvents(RW_EVENT::READ);
}

void MemRWer::push_signal(Signal s) {
    if (flags & RWER_CLOSING){
        return;
    }
    ConsumeRData(0);
    switch(s){
    case CHANNEL_ABORT:
        return errorCB(PROTOCOL_ERR, PEER_LOST_ERR);
    }
}

void MemRWer::push(std::variant<Buffer, Signal> data) {
    std::visit([this](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, Signal>) {
            push_signal(arg);
        } else if constexpr (std::is_same_v<T, Buffer>) {
            push_data(std::move(arg));
        }
    }, data);
}

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


void MemRWer::ConsumeRData(uint64_t id) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    bool keepReading = false;
    if(rb.length()){
        Buffer wb = rb.get();
        assert(wb.len != 0);
        wb.id = id;
        auto ret = readCB(std::move(wb));
        if(ret > 0) {
            rb.consume(ret);
            keepReading = true;
        }
    }
    if(rb.length() == 0 && isEof() && (flags & RWER_EOFDELIVED) == 0){
        keepReading = false;
        readCB({nullptr, id});
        flags |= RWER_EOFDELIVED;
    }
    if(!keepReading){
        delEvents(RW_EVENT::READ);
    }
}

ssize_t MemRWer::Write(std::set<uint64_t>& writed_list) {
    size_t len = 0;
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

void MemRWer::closeHE(RW_EVENT event) {
    if((flags & RWER_SHUTDOWN) == 0 && (stats == RWerStats::ReadEOF || stats == RWerStats::Connected)){
        flags |= RWER_SHUTDOWN;
        wbuff.emplace_back(nullptr);
    }
    RWer::closeHE(event); // NOLINT
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
        readCB({nullptr, bb.id});
        flags |= RWER_EOFDELIVED;
    } else {
        readCB(std::move(bb));
    }
}

void PMemRWer::ConsumeRData(uint64_t) {
    delEvents(RW_EVENT::READ);
}
