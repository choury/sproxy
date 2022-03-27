#include "rwer.h"
#include "common/common.h"
#include "misc/util.h"
#include "misc/net.h"

#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>

#ifdef __linux__
#include <sys/eventfd.h>
#endif

size_t RWer::wlength() {
    return wbuff.length();
}

ssize_t RWer::cap(uint64_t) {
    return 4 * 1024 * 1024 - wbuff.length();
}

buff_iterator WBuffer::start() {
    return write_queue.begin();
}

buff_iterator WBuffer::end() {
    return write_queue.end();
}

buff_iterator WBuffer::push(buff_iterator i, buff_block&& bb) {
    len += bb.len;
    return write_queue.emplace(i, std::move(bb));
}

ssize_t WBuffer::Write(std::function<ssize_t(const void*, size_t, uint64_t)> write_func){
    if(write_queue.empty()){
        return 0;
    }
    auto i = write_queue.begin();
    if(i->len == 0){
        ssize_t ret = write_func(nullptr, 0, i->id);
        if(ret < 0){
            return ret;
        }
        write_queue.pop_front();
        return Write(write_func);
    }
    assert(i->buff);
    assert(i->offset < i->len);
    ssize_t ret = write_func((const char*)i->buff + i->offset, i->len - i->offset, i->id);
    if (ret > 0) {
        assert(len >= (size_t)ret);
        len -= ret;
        assert(ret + i->offset <= i->len);
        if ((size_t)ret + i->offset == i->len) {
            write_queue.pop_front();
        } else {
            i->offset += ret;
        }
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

WBuffer::~WBuffer() {
    while(!write_queue.empty()){
        write_queue.pop_front();
    }
    len = 0;
}

RWer::RWer(int fd, std::function<void(int ret, int code)> errorCB):
    Ep(fd), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [](buff_block& bb){
        LOGE("discard data from stub readCB: %zd [%" PRIu64 "]\n", bb.len, bb.id);
        bb.offset = bb.len;
    };
    writeCB = [](size_t){};
}


RWer::RWer(std::function<void (int, int)> errorCB, std::function<void(const sockaddr_storage&)> connectCB):
           Ep(-1), connectCB(std::move(connectCB)), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    assert(this->connectCB != nullptr);
    readCB = [](buff_block& bb){
        LOGE("discard data from stub readCB: %zd [%" PRIu64 "]\n", bb.len, bb.id);
        bb.offset = bb.len;
    };
    writeCB = [](size_t){};
}

void RWer::SendData(){
    size_t writed = 0;
    while(wbuff.start() != wbuff.end()){
        int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2, _3));
        if(ret >= 0){
            writed += ret;
            continue;
        }
        if(errno == EAGAIN || errno == ENOBUFS){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(writed){
        writeCB(writed);
    }
    if(wbuff.start() == wbuff.end()){
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = std::move(func);
}

void RWer::SetReadCB(std::function<void(buff_block&)> func){
    readCB = std::move(func);
    EatReadData();
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
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
    if (!!(events & RW_EVENT::WRITE)){
        flags |= RWER_SENDING;
        SendData();
        flags &= ~RWER_SENDING;
    }
    if(stats == RWerStats::ReadEOF){
        delEvents(RW_EVENT::READ);
        flags |= RWER_READING;
        ConsumeRData();
        flags &= ~RWER_READING;
    }
}

void RWer::closeHE(RW_EVENT) {
    if(wbuff.start() == wbuff.end() || (flags & RWER_SHUTDOWN)){
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

void RWer::EatReadData(){
    if(flags & RWER_READING){
        return;
    }
    flags |= RWER_READING;
    switch(stats){
    case RWerStats::Connected:
        if(rlength()) {
            ConsumeRData();
        }
        addEvents(RW_EVENT::READ);
        break;
    case RWerStats::ReadEOF:
        ConsumeRData();
        break;
    default:
        break;
    }
    flags &= ~RWER_READING;
}

void RWer::Connected(const sockaddr_storage& addr){
    if(stats == RWerStats::Connected){
        return;
    }
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&RWer::defaultHE;
    connectCB(addr);
}

void RWer::ErrorHE(int ret, int code) {
    stats = RWerStats::Error;
    errorCB(ret, code);
}

void RWer::Shutdown() {
    flags |= RWER_SHUTDOWN;
    shutdown(getFd(), SHUT_WR);
}

buff_iterator RWer::buffer_head() {
    return wbuff.start();
}

buff_iterator RWer::buffer_end() {
    return wbuff.end();
}

buff_iterator RWer::buffer_insert(buff_iterator where, buff_block&& bb) {
    assert(bb.offset <= bb.len);
    assert((flags & RWER_SHUTDOWN) == 0);
    if(bb.offset < bb.len || bb.len == 0){
        addEvents(RW_EVENT::WRITE);
        return wbuff.push(where, std::move(bb));
    }else{
        return where;
    }
}

NullRWer::NullRWer():RWer(-1, [](int, int){}) {
}

void NullRWer::ReadData() {
}

size_t NullRWer::rlength() {
    return 0;
}

size_t NullRWer::wlength() {
    return 0;
}

void NullRWer::ConsumeRData() {
}

ssize_t NullRWer::Write(const void*, size_t len, uint64_t) {
    LOG("discard everything write to NullRWer\n");
    return len;
}

#ifdef __linux__
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB):
    RWer(errorCB, [](const sockaddr_storage&){})
{
    int evfd = eventfd(1, SOCK_CLOEXEC);
    if(evfd < 0){
        stats = RWerStats::Error;
        errorCB(SOCKET_ERR, errno);
        return;
    }
    setFd(evfd);
    write(evfd, "FULLEVENT", 8);
#else
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB):
    RWer(errorCB, [](const sockaddr_storage&){}), pairfd(-1){
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

size_t FullRWer::rlength() {
    return 1;
}

ssize_t FullRWer::cap(uint64_t) {
    return 0;
}

void FullRWer::ConsumeRData() {
    buff_block wb{(void*)nullptr, 1};
    readCB(wb);
}

void FullRWer::ReadData(){
    while(!!(events & RW_EVENT::READ)) {
        ConsumeRData();
    }
    Write("FULLEVENT", 8, 0);
}

void FullRWer::closeHE(RW_EVENT) {
    closeCB();
}

