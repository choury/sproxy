#include "memio.h"

MemRWer::MemRWer(const char* pname, std::function<int(Buffer&&)> cb):
    FullRWer([](int, int){}), cb(cb)
{
    strncpy(peer, pname, sizeof(peer));
}

MemRWer::~MemRWer() {
}

size_t MemRWer::rlength(uint64_t) {
    return rb.length();
}

ssize_t MemRWer::cap(uint64_t) {
    return rb.cap();
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


void MemRWer::push(Buffer&& bb) {
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        rb.put(bb.data(), bb.len);
    }
    addEvents(RW_EVENT::READ);
}

void MemRWer::ConsumeRData(uint64_t) {
    if(rb.length()){
        Buffer wb = rb.get();
        size_t left = readCB(0, wb.data(), wb.len);
        rb.consume(wb.len - left);
    }
    delEvents(RW_EVENT::READ);
    if(stats == RWerStats::ReadEOF && (flags & RWER_EOFDELIVED) == 0){
        readCB(0, nullptr, 0);
        flags |= RWER_EOFDELIVED;
    }
}

ssize_t MemRWer::Write(const Buffer &bb) {
    if(bb.len) {
        return cb(Buffer{bb.data(), bb.len, bb.id});
    }else{
        flags |= RWER_SHUTDOWN;
        return cb(Buffer{nullptr, bb.id});
    }
}

void MemRWer::closeHE(RW_EVENT event) {
    if((flags & RWER_SHUTDOWN) == 0){
        flags |= RWER_SHUTDOWN;
        wbuff.push(wbuff.end(), {nullptr});
    }
    RWer::closeHE(event);
}
