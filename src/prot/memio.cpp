#include "memio.h"

MemRWer::MemRWer(const char* pname, std::function<int(std::variant<Buffer, Signal>)> read_cb,
                 std::function<ssize_t()> cap_cb):
    FullRWer([](int, int){}), read_cb(std::move(read_cb)), cap_cb(std::move(cap_cb))
{
    snprintf(peer, sizeof(peer), "%s", pname);
}

MemRWer::~MemRWer() {
}

size_t MemRWer::rlength(uint64_t) {
    return rb.length();
}

ssize_t MemRWer::cap(uint64_t) {
    return cap_cb();
}

void MemRWer::SetConnectCB(std::function<void (const sockaddr_storage &)> cb){
    if(IsConnected()) {
        cb({});
    } else {
        connectCB = std::move(cb);
    }
}

void MemRWer::Close(std::function<void()> func) {
    if (getFd() >= 0) {
        RWer::Close([this, func = std::move(func)] {
            read_cb(CHANNEL_ABORT);
            func();
        });
    } else {
        // 已经收到了源端的ABORT信号
        func();
    }
}

void MemRWer::connected(const sockaddr_storage& addr) {
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&MemRWer::defaultHE;
    connectCB(addr);
    connectCB = [](const sockaddr_storage&){};
}

void MemRWer::push_data(const Buffer &bb) {
    assert(stats != RWerStats::ReadEOF);
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
        setFd(-1);
        return ErrorHE(PROTOCOL_ERR, PEER_LOST_ERR);
    }
}

void MemRWer::push(std::variant<Buffer, Signal> data) {
    std::visit([this](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, Signal>) {
            push_signal(arg);
        } else if constexpr (std::is_same_v<T, Buffer>) {
            push_data(arg);
        }
    }, data);
}

void MemRWer::detach() {
    read_cb = [](std::variant<Buffer, Signal> data) -> int{
        if(auto bb = std::get_if<Buffer>(&data)) {
            return (int)bb->len;
        }
        return 0;
    };
    cap_cb = []{return 0;};
}


void MemRWer::ConsumeRData(uint64_t id) {
    if(rb.length()){
        Buffer wb = rb.get();
        wb.id = id;
        size_t left = readCB(wb);
        rb.consume(wb.len - left);
    }
    delEvents(RW_EVENT::READ);
    if(isEof() && (flags & RWER_EOFDELIVED) == 0){
        readCB(nullptr);
        flags |= RWER_EOFDELIVED;
    }
}

ssize_t MemRWer::Write(const std::list<Buffer>& bbs) {
    size_t len = 0;
    for(const auto& bb : bbs) {
        ssize_t ret = 0;
        if (bb.len) {
            ret = read_cb(Buffer{std::make_shared<Block>(bb.data(), bb.len), bb.len, bb.id});
        } else {
            assert(flags & RWER_SHUTDOWN);
            ret = read_cb(Buffer{nullptr, bb.id});
        }
        if(ret < 0){
            return ret;
        }
        len += ret;
        if((size_t)ret != bb.len) {
            break;
        }
    }
    return (ssize_t)len;
}

void MemRWer::closeHE(RW_EVENT event) {
    if((flags & RWER_SHUTDOWN) == 0 && (stats == RWerStats::ReadEOF || stats == RWerStats::Connected)){
        flags |= RWER_SHUTDOWN;
        wbuff.push(wbuff.end(), {nullptr});
    }
    RWer::closeHE(event); // NOLINT
}

void PMemRWer::push_data(const Buffer &bb) {
    assert(stats != RWerStats::ReadEOF);
    if(flags & RWER_CLOSING){
        return;
    }
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
        readCB(nullptr);
        flags |= RWER_EOFDELIVED;
    } else {
        readCB(bb);
    }
}

void PMemRWer::ConsumeRData(uint64_t) {
    delEvents(RW_EVENT::READ);
}