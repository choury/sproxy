#include "rwer.h"
#include "common/common.h"
#include "misc/defer.h"
#include "misc/hook.h"

#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <set>
#include <sys/uio.h>
#include <limits.h>

#ifdef __linux__
#include <sys/eventfd.h>
#else
#include "misc/net.h"
#endif

ssize_t RWer::cap(uint64_t) {
    return wbuff.cap();
}

bool RWer::drained() {
    return wbuff.empty();
}

RWer::RWer(int fd, std::shared_ptr<IRWerCallback> cb): Ep(fd), callback(std::move(cb)) {
    assert(cb && cb->errorCB);
}


RWer::RWer(std::shared_ptr<IRWerCallback> cb): Ep(-1), callback(std::move(cb)) {
    assert(cb && cb->errorCB);
}

ssize_t RWer::Write(std::set<uint64_t>& writed_list) {
    ssize_t ret = 0;
    size_t len = 0;
    bool hasEof = false;
    if(drained()) {
        return 0;
    }
    const auto& data = wbuff.data();
    if(data.size() == 1) {
        auto &bb = data.front();
        if(likely(bb.len > 0)) {
            ret = write(getFd(), bb.data(), bb.len);
            LOGD(DRWER, "write %d: len: %zd, ret: %zd\n", getFd(), bb.len, ret);
            len = bb.len;
        } else {
            hasEof = true;
        }
    } else {
        std::vector<iovec> iovs;
        iovs.reserve(data.size());
        for (const auto &bb: data) {
            if (unlikely(bb.len == 0)) {
                //bb.len == 0 must be the last one
                hasEof = true;
                break;
            }
            iovs.emplace_back(iovec{(void *) bb.data(), bb.len});
            len += bb.len;
            if (unlikely(iovs.size() >= IOV_MAX)) {
                break;
            }
        }
        ret = writev(getFd(), iovs.data(), iovs.size());
        if(ret > 0) {
            LOGD(DRWER, "writev %d: iovs: %zd, ret: %zd/%zd\n", getFd(), iovs.size(), ret, len);
        } else {
            LOGE("writev %d error: %s\n", getFd(), strerror(errno));
        }
    }
    if(len == (size_t)ret && hasEof) {
        LOGD(DRWER, "shutdown: %d\n", getFd());
        assert(flags & RWER_SHUTDOWN);
        shutdown(getFd(), SHUT_WR);
    }
    if(ret >= 0){
        writed_list = wbuff.consume(ret);
    }
    return ret;
}

void RWer::SendData(){
    std::set<uint64_t> writed_list;
    int ret = Write(writed_list);
    if(ret >= 0){
        //normal, do nothing
    }else if (errno != EAGAIN && errno != ENOBUFS && errno != EINTR) {
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(auto cb = callback.lock(); cb) {
        for(auto id: writed_list){
            cb->writeCB(id);
        }
    }
    if(drained()){
        assert(wbuff.empty());
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetCallback(std::shared_ptr<IRWerCallback> cb) {
    LOGD(DRWER, "set callback %d: %p\n", getFd(), cb.get());
    callback = std::move(cb);
    ConsumeRData(0);
}

#if 0
void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = std::move(func);
}

void RWer::SetReadCB(std::function<size_t(Buffer&& bb)> func){
    readCB = std::move(func);
    Unblock(0);
}

void RWer::SetWriteCB(std::function<void(uint64_t id)> func){
    writeCB = std::move(func);
}

void RWer::ClearCB() {
    readCB = [](Buffer&&){ return 0;};
    writeCB = [](uint64_t){};
    errorCB = [](int, int){};
    closeCB = []{};
}
#endif


void RWer::defaultHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR)) {
        ErrorHE(SOCKET_ERR, checkSocket(__PRETTY_FUNCTION__));
    }
    if((flags & RWER_CLOSING) || stats == RWerStats::Error){
        return;
    }
    if (!!(events & RW_EVENT::READ) || !!(events & RW_EVENT::READEOF)){
        ReadData();
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
    ssize_t ret = Write(writed_list);
#ifndef WSL
    if (drained() || (ret <= 0 && errno != EAGAIN && errno != ENOBUFS)) {
        handleEvent = (void(Ep::*)(RW_EVENT))&RWer::IdleHE;
        setEvents(RW_EVENT::NONE);
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
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

bool RWer::isTls() {
    return false;
}


bool RWer::isEof() {
    return stats == RWerStats::ReadEOF;
}

bool RWer::IsConnected(){
    return stats == RWerStats::Connected;
}


void RWer::Close() {
    if(flags & RWER_CLOSING){
        return;
    }
    flags |= RWER_CLOSING;
    //closeCB = std::move(func);
    if(getFd() >= 0 && (stats == RWerStats::Connected || stats == RWerStats::ReadEOF || stats == RWerStats::Error)){
        setEvents(RW_EVENT::READWRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::IdleHE;
        // when connecting, the socket is not writable, so we close it immediately
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    }
}

void RWer::Unblock(uint64_t id){
    LOGD(DRWER, "unblock %d: <%" PRIu64 "> rlength: %zd, flags: 0x%x, stats: %d, events: %d\n",
        getFd(), id, rlength(id), flags, (int)stats, (int)events);
    if (flags & RWER_READING) {
        return;
    }
    switch(stats){
    case RWerStats::Connected:
        if(!!(events & RW_EVENT::READ)){
            break;
        }
        addEvents(RW_EVENT::READ);
        if(rlength(id) > 0) {
            ConsumeRData(id);
        }
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
}

void RWer::ErrorHE(int ret, int code) {
    stats = RWerStats::Error;
    if (auto cb = callback.lock(); cb) {
        cb->errorCB(ret, code);
    }
}


void RWer::Send(Buffer&& bb) {
    assert((flags & RWER_SHUTDOWN) == 0);
    if(bb.len == 0){
        flags |= RWER_SHUTDOWN;
    }
    addEvents(RW_EVENT::WRITE);
    LOGD(DRWER, "push to wbuff %d: id: %" PRIu64", len: %zd, refs: %zd, wlen: %zd\n",
        getFd(), bb.id, bb.len, bb.refs(), wbuff.length());
    wbuff.put(std::move(bb));
}

bool RWer::idle(uint64_t) {
    if (getFd() < 0) {
        return true;
    }
    return (flags & RWER_SHUTDOWN) && (flags & RWER_EOFDELIVED);
}

NullRWer::NullRWer():RWer(-1, IRWerCallback::create()->onError([](int, int){})) {
}

void NullRWer::ReadData() {
}

size_t NullRWer::rlength(uint64_t) {
    return 0;
}

void NullRWer::ConsumeRData(uint64_t) {
}

ssize_t NullRWer::Write(std::set<uint64_t>& writed_list) {
    auto wlen = wbuff.length();
    LOG("discard everything write to NullRWer, size: %zd\n", wlen);
    writed_list = wbuff.consume(wlen);
    return wlen;
}

#ifdef __linux__
FullRWer::FullRWer(std::shared_ptr<IRWerCallback> cb): RWer(std::move(cb)) {
    int evfd = eventfd(1, SOCK_CLOEXEC);
    if(evfd < 0){
        stats = RWerStats::Error;
        if(auto cb = callback.lock(); cb) {
            cb->errorCB(SOCKET_ERR, errno);
        }
        return;
    }
    setFd(evfd);
    (void)!write(evfd, "FULLEVENT", 8);
#else
FullRWer::FullRWer(std::shared_ptr<IRWerCallback> cb): RWer(std::move(cb)), pairfd(-1){
    int pairs[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
    if(ret){
        stats = RWerStats::Error;
        if(auto cb = callback.lock(); cb) {
            cb->errorCB(SOCKET_ERR, errno);
        }
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

ssize_t FullRWer::Write(std::set<uint64_t>&) {
    return 0;
}

size_t FullRWer::rlength(uint64_t) {
    return SIZE_MAX;
}

ssize_t FullRWer::cap(uint64_t) {
    return SIZE_MAX;
}

void FullRWer::ConsumeRData(uint64_t id) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    if(auto cb = callback.lock(); cb) {
        cb->readCB({nullptr, id});
    }
}

void FullRWer::ReadData(){
    ConsumeRData(0);
}

void FullRWer::closeHE(RW_EVENT) {
    setEvents(RW_EVENT::NONE);
    if(auto cb = callback.lock(); cb) {
        cb->closeCB();
    }
}

