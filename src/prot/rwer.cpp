#include "rwer.h"
#include "common.h"
#include "misc/util.h"
#include "misc/net.h"

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

const char *events_string[]= {
    "NULL",
    "READ",
    "WRITE",
    "READ|WRITE",
    "READEOF",
    "READEOF|READ",
    "READEOF|WRITE",
    "READEOF|READ|WRITE",
    "ERROR",
    "ERROR|READ",
    "ERROR|WRITE",
    "ERROR|READ|WRITE",
    "ERROR|READEOF",
    "ERROR|READEOF|READ",
    "ERROR|READEOF|WRITE",
    "ERROR|READEOF|READ|WRITE",
};

extern int efd;

RW_EVENT operator&(RW_EVENT a, RW_EVENT b){
    return RW_EVENT(int(a) & int(b));
}

RW_EVENT operator|(RW_EVENT a, RW_EVENT b){
    return RW_EVENT(int(a) | int(b));
}

RW_EVENT operator~(RW_EVENT a){
    return RW_EVENT(~static_cast<int>(a));
}

bool operator!(RW_EVENT a){
    return a == RW_EVENT::NONE;
}

#ifdef __linux__
RW_EVENT convertEpoll(uint32_t events){
    RW_EVENT rwevents = RW_EVENT::NONE;
    if((events & EPOLLHUP) || (events & EPOLLERR)){
        rwevents = rwevents | RW_EVENT::ERROR;
    }
    if(events & EPOLLIN){
        rwevents = rwevents | RW_EVENT::READ;
    }
    if(events & EPOLLRDHUP){
        rwevents = rwevents | RW_EVENT::READEOF;
    }
    if(events & EPOLLOUT){
        rwevents = rwevents | RW_EVENT::WRITE;
    }
    return rwevents;
}
#endif

#ifdef __APPLE__
RW_EVENT convertKevent(const struct kevent& event){
    RW_EVENT rwevent = RW_EVENT::NONE;
    if(event.flags & EV_ERROR){
        rwevent = rwevent | RW_EVENT::ERROR;
    }
    if (event.flags & EV_EOF){
        rwevent = rwevent | RW_EVENT::READEOF;
    }
    if (event.filter == EVFILT_READ){
        rwevent = rwevent | RW_EVENT::READ;
    }
    if (event.filter == EVFILT_WRITE){
        rwevent = rwevent | RW_EVENT::WRITE;
    }
    return rwevent;
}
#endif

static void setSocketUnblock(int fd){
    if(fd < 0){
        return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0){
        LOGE("fcntl error: %s\n", strerror(errno));
        return;
    }
    int ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if(ret < 0){
        LOGE("fcntl error: %s\n", strerror(errno));
    }
}

Ep::Ep(int fd):fd(fd){
    LOGD(DEVENT, "%p set fd: %d\n", this, fd);
    setSocketUnblock(fd);
}

Ep::~Ep(){
    if(fd >= 0){
        LOGD(DEVENT, "closed %d\n", fd);
        close(fd);
    }
}

void Ep::setFd(int fd){
    if(this->fd >= 0){
        LOGD(DEVENT, "closed %d\n", fd);
        close(this->fd);
        events = RW_EVENT::NONE;
    }
    this->fd = fd;
    LOGD(DEVENT, "%p set fd: %d\n", this, fd);
    setSocketUnblock(fd);
}

int Ep::getFd(){
    return fd;
}

void Ep::setEvents(RW_EVENT events) {
    if(events == this->events){
        return;
    }
    if (fd >= 0) {
#ifdef __linux__
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLHUP | EPOLLERR;
        if(!!(events & RW_EVENT::READ)){
            event.events |= EPOLLIN | EPOLLRDHUP;
        }
        if(!!(events & RW_EVENT::WRITE)){
            event.events |= EPOLLOUT;
        }
        int ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        if (ret && errno == ENOENT) {
            ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
            if(ret){
                LOGE("epoll_ctl add failed:%s\n", strerror(errno));
                return;
            }
        }else if(ret){
            LOGE("epoll_ctl mod failed:%s\n", strerror(errno));
            return;
        }
#endif
#ifdef __APPLE__
        struct kevent event[2];
        int count = 0;
        if(!!(events & RW_EVENT::READ)){
            EV_SET(&event[count++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void*)(intptr_t)this);
        }else if(!!(this->events & RW_EVENT::READ)){
            EV_SET(&event[count++], fd, EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0, (void*)(intptr_t)this);
        }
        if(!!(events & RW_EVENT::WRITE)){
            EV_SET(&event[count++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void*)(intptr_t)this);
        }else if(!!(this->events & RW_EVENT::WRITE)){
            EV_SET(&event[count++], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, (void*)(intptr_t)this);
        }
        int ret = kevent(efd, event, count, NULL, 0, NULL);
        if(ret < 0){
            LOGE("kevent failed:%s\n", strerror(errno));
            return;
        }
#endif
#ifndef NDEBUG
        if(events != this->events) {
            assert(int(events) <= 3);
            LOGD(DEVENT, "modify %d: %s --> %s\n", fd, events_string[int(this->events)], events_string[int(events)]);
        }
#endif
        this->events = events;
    }
}

void Ep::addEvents(RW_EVENT events){
    return setEvents(this->events | events);
}

void Ep::delEvents(RW_EVENT events){
    return setEvents(this->events & ~events);
}

RW_EVENT Ep::getEvents(){
    return this->events;
}

int Ep::checkSocket(const char* msg){
    return Checksocket(fd, msg);
}

size_t RWer::wlength() {
    return wbuff.length();
}

std::list<write_block>::iterator WBuffer::start() {
    return write_queue.begin();
}

std::list<write_block>::iterator WBuffer::end() {
    return write_queue.end();
}

std::list<write_block>::iterator WBuffer::push(std::list<write_block>::insert_iterator i, const write_block& wb) {
    assert(wb.buff);
    len += wb.len;
    return write_queue.emplace(i, wb);
}

ssize_t WBuffer::Write(std::function<ssize_t(const void*, size_t)> write_func){
    auto wb = *write_queue.begin();
    write_queue.pop_front();
    assert(wb.buff);
    if(wb.len == 0){
        p_free(wb.buff);
        return 0;
    }
    assert(wb.offset < wb.len);
    ssize_t ret = write_func((const char *)wb.buff + wb.offset, wb.len - wb.offset);
    if (ret > 0) {
        assert(len >= (size_t)ret);
        len -= ret;
        assert(ret + wb.offset <= wb.len);
        if ((size_t)ret + wb.offset == wb.len) {
            p_free(wb.buff);
        } else {
            wb.offset += ret;
            write_queue.push_front(wb);
        }
    }else{
        write_queue.push_front(wb);
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

void WBuffer::clear(bool freebuffer){
    if(freebuffer){
        while(!write_queue.empty()){
            p_free(write_queue.begin()->buff);
            write_queue.pop_front();
        }
    }else{
        write_queue.clear();
    }
    len = 0;
}

WBuffer::~WBuffer() {
    clear(true);
}

RWer::RWer(int fd, std::function<void(int ret, int code)> errorCB):
    Ep(fd), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [this](size_t len){
        LOGE("discard data from stub readCB: %zd", len);
        consume(rdata(), len);
    };
    writeCB = [](size_t){};
}


RWer::RWer(std::function<void (int, int)> errorCB, std::function<void(const union sockaddr_un&)> connectCB):
           Ep(-1), connectCB(std::move(connectCB)), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    assert(this->connectCB != nullptr);
    readCB = [this](size_t len){
        LOGE("discard data from stub readCB: %zd", len);
        consume(rdata(), len);
    };
    writeCB = [](size_t){};
}

void RWer::SendData(){
    size_t writed = 0;
    while(wbuff.length()){
        int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
        if(ret >= 0){
            writed += ret;
            continue;
        }
        if(errno == EAGAIN){
            break;
        }
        errorCB(WRITE_ERR, errno);
        return;
    }
    if(writed){
        writeCB(writed);
    }
    if(wbuff.length() == 0){
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = std::move(func);
}

void RWer::SetReadCB(std::function<void(size_t len)> func){
    readCB = std::move(func);
    EatReadData();
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
    writeCB = std::move(func);
}

void RWer::defaultHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR)) {
        errorCB(SOCKET_ERR, checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ) || !!(events & RW_EVENT::READEOF)){
        ReadData();
    }
    if (!!(events & RW_EVENT::WRITE)){
        SendData();
    }
    if(stats == RWerStats::ReadEOF){
        delEvents(RW_EVENT::READ);
        if(rlength() == 0){
            errorCB(READ_ERR, 0);
        }
    }
}

void RWer::closeHE(RW_EVENT) {
    if(wbuff.length() == 0){
        closeCB();
        return;
    }
    int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
#ifndef WSL
    if ((wbuff.length() == 0) || (ret <= 0 && errno != EAGAIN)) {
        closeCB();
    }
#else
    if ((wbuff.length() == 0) || (ret <= 0)) {
        closeCB();
    }
#endif
}

bool RWer::supportReconnect(){
    return false;
}

void RWer::Reconnect() {
}

void RWer::Close(std::function<void()> func) {
    closeCB = std::move(func);
    if(getFd() >= 0){
        setEvents(RW_EVENT::READWRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        closeCB();
    }
}

void RWer::EatReadData(){
    switch(stats){
    case RWerStats::Connected:
        if(rlength()){
            readCB(rlength());
        }
        addEvents(RW_EVENT::READ);
        break;
    case RWerStats::ReadEOF:
        if(rlength()){
            readCB(rlength());
        }else{
            errorCB(READ_ERR, 0);
        }
        break;
    default:
        break;
    }
}

void RWer::Connected(const union sockaddr_un& addr){
    stats = RWerStats::Connected;
    connectCB(addr);
}

void RWer::Shutdown() {
    stats = RWerStats::Shutdown;
    shutdown(getFd(), SHUT_WR);
}

std::list<write_block>::insert_iterator RWer::buffer_head() {
    return wbuff.start();
}

std::list<write_block>::insert_iterator RWer::buffer_end() {
    return wbuff.end();
}

std::list<write_block>::insert_iterator
RWer::buffer_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    assert(wb.offset <= wb.len);
    if(wb.offset < wb.len || wb.len == 0){
        addEvents(RW_EVENT::WRITE);
        return wbuff.push(where, wb);
    }else{
        p_free(wb.buff);
        return where;
    }
}

void RWer::Clear(bool freebuffer) {
    wbuff.clear(freebuffer);
}

NullRWer::NullRWer():RWer(-1, [](int, int){}) {
}

void NullRWer::consume(const char*, size_t) {
    LOGE("NullRWer consume was called\n");
    abort();
}

void NullRWer::ReadData() {
}

size_t NullRWer::rleft() {
    return 0;
}

size_t NullRWer::rlength() {
    return 0;
}

size_t NullRWer::wlength() {
    return 0;
}

ssize_t NullRWer::Write(const void*, size_t len) {
    LOG("discard everything write to NullRWer\n");
    return len;
}

const char * NullRWer::rdata() {
    return nullptr;
}