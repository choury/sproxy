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
    readCB = [](const Buffer& bb) -> size_t {
        LOGE("send data to stub readCB: %zd [%" PRIu64 "]\n", bb.len, bb.id);
        return bb.len;
    };
    writeCB = [](size_t){};
}


RWer::RWer(std::function<void (int, int)> errorCB): Ep(-1), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [](const Buffer& bb){return bb.len;};
    writeCB = [](size_t){};
}

ssize_t RWer::Write(const Buffer& bb) {
    if(bb.len == 0) {
        assert(flags & RWER_SHUTDOWN);
        shutdown(getFd(), SHUT_WR);
        return 0;
    }
    return write(getFd(), bb.data(), bb.len);
}

void RWer::SendData(){
    std::set<uint64_t> writed_list;
    while(wbuff.start() != wbuff.end()){
        int ret = wbuff.Write(std::bind(&RWer::Write, this, _1), writed_list);
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

void RWer::SetReadCB(std::function<size_t(Buffer bb)> func){
    readCB = std::move(func);
    Unblock(0);
}

void RWer::SetWriteCB(std::function<void(uint64_t id)> func){
    writeCB = std::move(func);
}

void RWer::defaultHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR)) {
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
    std::set<uint64_t> writed_list;
    ssize_t ret = wbuff.Write(std::bind(&RWer::Write, this, _1), writed_list);
#ifndef WSL
    if ((wbuff.start() == wbuff.end()) || (ret <= 0 && errno != EAGAIN && errno != ENOBUFS)) {
        handleEvent = (void(Ep::*)(RW_EVENT))&RWer::IdleHE;
        setEvents(RW_EVENT::NONE);
        closeCB();
    }
#else
    if ((wbuff.start() == wbuff.end()) || (ret <= 0)) {
        handleEvent = (void(Ep::*)(RW_EVENT))&RWer::IdleHE;
        setEvents(RW_EVENT::NONE);
        closeCB();
    }
#endif
}

void RWer::IdleHE(RW_EVENT) {
    setEvents(RW_EVENT::NONE);
}

bool RWer::IsEOF() {
    return stats == RWerStats::ReadEOF;
}

void RWer::Close(std::function<void()> func) {
    if(flags & RWER_CLOSING){
        return;
    }
    flags |= RWER_CLOSING;
    closeCB = std::move(func);
    if(getFd() >= 0 && (stats == RWerStats::Connected || stats == RWerStats::ReadEOF || stats == RWerStats::Error)){
        setEvents(RW_EVENT::READWRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::IdleHE;
        // when connecting, the socket is not writable, so we close it immediately
        closeCB();
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


void RWer::buffer_insert(Buffer&& bb) {
    assert((flags & RWER_SHUTDOWN) == 0);
    if(bb.len == 0){
        flags |= RWER_SHUTDOWN;
    }
    addEvents(RW_EVENT::WRITE);
    wbuff.push(wbuff.end(), std::move(bb));
}

bool RWer::idle(uint64_t) {
    if (getFd() < 0) {
        return true;
    }
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

ssize_t NullRWer::Write(const Buffer& bb) {
    LOG("discard everything write to NullRWer, size: %zd\n", bb.len);
    return bb.len;
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
    (void)!write(evfd, "FULLEVENT", 8);
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
    (void)!write(pairfd, "FULLEVENT", 8);
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

ssize_t FullRWer::Write(const Buffer&) {
    return 0;
}

size_t FullRWer::rlength(uint64_t) {
    return SIZE_MAX;
}

ssize_t FullRWer::cap(uint64_t) {
    return SIZE_MAX;
}

void FullRWer::ConsumeRData(uint64_t id) {
    readCB({nullptr, id});
}

void FullRWer::ReadData(){
    ConsumeRData(0);
}

void FullRWer::closeHE(RW_EVENT) {
    closeCB();
}

