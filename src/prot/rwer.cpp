#include "rwer.h"
#include "common/common.h"
#include "misc/net.h"

#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <set>

#ifdef __linux__
#include <sys/eventfd.h>
#endif

ssize_t RWer::cap(uint64_t) {
    return MAX_BUF_LEN - wbuff.length();
}

RWer::RWer(int fd, std::function<void(int ret, int code)> errorCB):
    Ep(fd), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [](uint64_t id, const void*, size_t len) -> size_t {
        LOGE("discard data from stub readCB: %zd [%" PRIu64 "]\n", len, id);
        return 0;
    };
    writeCB = [](size_t){};
}


RWer::RWer(std::function<void (int, int)> errorCB): Ep(-1), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [](uint64_t id, const void*, size_t len) -> size_t {
        LOGE("discard data from stub readCB: %zd [%" PRIu64 "]\n", len, id);
        return 0;
    };
    writeCB = [](size_t){};
}

void RWer::SendData(){
    std::set<uint64_t> writed_list;
    while(wbuff.start() != wbuff.end()){
        int ret = wbuff.Write(std::bind([this, &writed_list] (const void* buff, size_t len, uint64_t id) mutable {
            auto ret =  Write(buff, len, id);
            if(ret >= 0){
                writed_list.insert(id);
            }
            return ret;
        }, _1, _2, _3));
        if(ret >= 0){
            continue;
        }
        if(errno == EAGAIN || errno == ENOBUFS){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    for(auto id: writed_list){
        writeCB(id);
    }
    if(wbuff.start() == wbuff.end()){
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = std::move(func);
}

void RWer::SetReadCB(std::function<size_t(uint64_t id, const void* data, size_t len)> func){
    readCB = std::move(func);
    Unblock(0);
}

void RWer::SetWriteCB(std::function<void(uint64_t id)> func){
    writeCB = std::move(func);
}

void RWer::defaultHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR) || stats == RWerStats::Error) {
        ErrorHE(SOCKET_ERR, checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ) || !!(events & RW_EVENT::READEOF)){
        flags |= RWER_READING;
        ReadData();
        flags &= ~RWER_READING;
    }
    if((flags & RWER_CLOSING) || stats == RWerStats::Error){
        return;
    }
    if (!!(events & RW_EVENT::WRITE)){
        flags |= RWER_SENDING;
        SendData();
        flags &= ~RWER_SENDING;
    }
}

void RWer::closeHE(RW_EVENT) {
    if(wbuff.start() == wbuff.end()){
        closeCB();
        return;
    }
    ssize_t ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2, _3));
#ifndef WSL
    if ((wbuff.start() == wbuff.end()) || (ret <= 0 && errno != EAGAIN && errno != ENOBUFS)) {
        closeCB();
    }
#else
    if ((wbuff.start() == wbuff.end()) || (ret <= 0)) {
        closeCB();
    }
#endif
}

void RWer::Close(std::function<void()> func) {
    if(flags & RWER_CLOSING){
        return;
    }
    flags |= RWER_CLOSING;
    closeCB = std::move(func);
    if(getFd() >= 0 && stats != RWerStats::Connecting){
        setEvents(RW_EVENT::READWRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        // when connecting, the socket is not writable, so we close it immediately
        addjob(closeCB, 0, JOB_FLAGS_AUTORELEASE);
    }
}

void RWer::Unblock(uint64_t id){
    if(flags & RWER_READING){
        return;
    }
    flags |= RWER_READING;
    switch(stats){
    case RWerStats::Connected:
        if(rlength(id) > 0) {
            ConsumeRData(id);
        }
        addEvents(RW_EVENT::READ);
        break;
    case RWerStats::ReadEOF:
        if(flags & RWER_EOFDELIVED){
            break;
        }
        ConsumeRData(id);
        break;
    default:
        break;
    }
    flags &= ~RWER_READING;
}

void RWer::ErrorHE(int ret, int code) {
    stats = RWerStats::Error;
    errorCB(ret, code);
}


buff_iterator RWer::buffer_head() {
    return wbuff.start();
}

buff_iterator RWer::buffer_end() {
    return wbuff.end();
}

buff_iterator RWer::buffer_insert(buff_iterator where, Buffer&& bb) {
    assert((flags & RWER_SHUTDOWN) == 0);
    if(bb.len == 0){
        flags |= RWER_SHUTDOWN;
    }
    addEvents(RW_EVENT::WRITE);
    return wbuff.push(where, std::move(bb));
}

bool RWer::idle(uint64_t) {
    return (flags & RWER_SHUTDOWN) && (flags & RWER_EOFDELIVED);
}

NullRWer::NullRWer():RWer(-1, [](int, int){}) {
}

void NullRWer::ReadData() {
}

size_t NullRWer::rlength(uint64_t) {
    return 0;
}

void NullRWer::ConsumeRData(uint64_t) {
}

ssize_t NullRWer::Write(const void*, size_t len, uint64_t) {
    LOG("discard everything write to NullRWer\n");
    return len;
}

#ifdef __linux__
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB): RWer(errorCB) {
    int evfd = eventfd(1, SOCK_CLOEXEC);
    if(evfd < 0){
        stats = RWerStats::Error;
        errorCB(SOCKET_ERR, errno);
        return;
    }
    setFd(evfd);
    write(evfd, "FULLEVENT", 8);
#else
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB): RWer(errorCB), pairfd(-1){
    int pairs[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
    if(ret){
        stats = RWerStats::Error;
        errorCB(SOCKET_ERR, errno);
        return;
    }
    setFd(pairs[0]);
    // pairfd should set noblock manually
    pairfd = pairs[1];
    SetSocketUnblock(pairfd);
    write(pairfd, "FULLEVENT", 8);
#endif
    setEvents(RW_EVENT::READ);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&FullRWer::defaultHE;
}

FullRWer::~FullRWer(){
#ifndef __linux__
    if(pairfd >= 0){
        close(pairfd);
    }
#endif
}

ssize_t FullRWer::Write(const void* buff, size_t len, uint64_t) {
#ifdef __linux__
    return write(getFd(), buff, len);
#else
    return write(pairfd, buff, len);
#endif
}

size_t FullRWer::rlength(uint64_t) {
    return 1;
}

ssize_t FullRWer::cap(uint64_t) {
    return 1;
}

void FullRWer::ConsumeRData(uint64_t) {
    readCB(0, nullptr, 0);
}

void FullRWer::ReadData(){
    ConsumeRData(0);
}

void FullRWer::closeHE(RW_EVENT) {
    closeCB();
}

