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

Ep::Ep(int fd):fd(fd){
    if(fd >= 0){
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n", strerror(errno));
            return;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

Ep::~Ep(){
    if(fd >= 0){
        LOGD(DEVENT, "closed %d\n", fd);
        close(fd);
        fd = -1;
    }
}

void Ep::setFd(int fd){
    if(this->fd >= 0){
        LOGD(DEVENT, "closed %d\n", fd);
        close(this->fd);
        events = RW_EVENT::NONE;
    }
    this->fd = fd;
    if(fd >= 0){
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n", strerror(errno));
            return;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
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
        event.events = EPOLLHUP | EPOLLERR | EPOLLRDHUP;
        if(!!(events & RW_EVENT::READ)){
            event.events |= EPOLLIN;
        }
        if(!!(events & RW_EVENT::WRITE)){
            event.events |= EPOLLOUT;
        }
        int ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        if (ret && errno == ENOENT) {
            ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
            if(ret != 0){
                LOGE("epoll_ctl add failed:%s\n", strerror(errno));
            }
        }else if(ret){
            LOGE("epoll_ctl mod failed:%s\n", strerror(errno));
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
    return setEvents(static_cast<RW_EVENT>(this->events | events));
}

void Ep::delEvents(RW_EVENT events){
    return setEvents(static_cast<RW_EVENT>(this->events & ~events));
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
    assert(wb.len);
    len += wb.len;
    return write_queue.emplace(i, wb);
}

ssize_t  WBuffer::Write(std::function<ssize_t(const void*, size_t)> write_func){
    auto i = write_queue.begin();
    assert(i->buff);
    assert(i->offset < i->len);
    ssize_t ret = write_func((char *)i->buff + i->offset, i->len - i->offset);
    if (ret > 0) {
        len -= ret;
        assert(ret + i->offset <= i->len);
        if ((size_t)ret + i->offset == i->len) {
            p_free(i->buff);
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

RWer::RWer(std::function<void (int, int)> errorCB,
           std::function<void(const union sockaddr_un*)> connectCB,
           int fd):Ep(fd), errorCB(errorCB), connectCB(connectCB) {
}

void RWer::SendData(){
    size_t writed = 0;
    while(wbuff.length()){
        int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
        assert(ret != 0);
        if(ret > 0){
            writed += ret;
            continue;
        }
        if(errno == EAGAIN){
            break;
        }
        errorCB(WRITE_ERR, errno);
        return;
    }
    if(writed && writeCB){
        writeCB(writed);
    }
    if(wbuff.length() == 0){
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = func;
}

void RWer::SetReadCB(std::function<void(size_t len)> func){
    readCB = func;
    TrigRead();
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
    writeCB = func;
}

void RWer::closeHE(uint32_t) {
    if(wbuff.length() == 0){
        closeCB();
        return;
    }
    int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
#ifndef WSL
    if ((wbuff.length() == 0) || (ret <= 0 && errno != EAGAIN)) {
        closeCB();
        return;
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


void RWer::TrigRead(){
    if(rlength() && readCB){
        readCB(rlength());
    }
}

void RWer::Close(std::function<void()> func) {
    closeCB = func;
    if(getFd() >= 0){
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        closeCB();
    }
}

void RWer::Shutdown() {
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
    if(wb.offset < wb.len){
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

