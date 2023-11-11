#include "memio.h"

MemRWer::MemRWer(const char* pname, std::function<int(Buffer&&)> read_cb, std::function<ssize_t()> cap_cb):
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


void MemRWer::connected(const sockaddr_storage& addr) {
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&MemRWer::defaultHE;
    connectCB(addr);
    connectCB = [](const sockaddr_storage&){};
}


void MemRWer::push(const Buffer& bb) {
    assert(stats != RWerStats::ReadEOF);
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        rb.put(bb.data(), bb.len);
    }
    addEvents(RW_EVENT::READ);
}

void MemRWer::injection(int error, int code) {
    if (flags & RWER_CLOSING){
        return;
    }
    return ErrorHE(error, code);
}

void MemRWer::detach() {
    read_cb = [](Buffer&& bb){ return bb.len;};
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
    if(IsEOF() && (flags & RWER_EOFDELIVED) == 0){
        readCB(nullptr);
        flags |= RWER_EOFDELIVED;
    }
}

ssize_t MemRWer::Write(const Buffer &bb) {
    if(bb.len) {
        return read_cb(Buffer{std::make_shared<Block>(bb.data(), bb.len), bb.len, bb.id});
    }else{
        assert(flags & RWER_SHUTDOWN);
        return read_cb(Buffer{nullptr, bb.id});
    }
}

void MemRWer::closeHE(RW_EVENT event) {
    if((flags & RWER_SHUTDOWN) == 0){
        flags |= RWER_SHUTDOWN;
        wbuff.push(wbuff.end(), {nullptr});
    }
    RWer::closeHE(event);
}

void PMemRWer::push(const Buffer &bb) {
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