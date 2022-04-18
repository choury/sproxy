//
// Created by 周威 on 2021/4/21.
//

#include "ep.h"
#include "common/common.h"
#include "misc/net.h"

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <map>

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

extern int efd;

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
static RW_EVENT convertEpoll(uint32_t events){
    RW_EVENT rwevents = RW_EVENT::NONE;
    //ingore EPOLLHUP
    if(events & EPOLLERR){
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
static RW_EVENT convertKevent(const struct kevent& event){
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
    LOGD(DEVENT, "%p set fd: %d\n", this, fd);
    SetSocketUnblock(fd);
}

Ep::~Ep(){
    if(fd >= 0){
        LOGD(DEVENT, "%p closed %d\n", this, fd);
        close(fd);
    }
}

void Ep::setFd(int fd){
    if(this->fd >= 0){
        LOGD(DEVENT, "%p closed %d\n", this, this->fd);
#if __linux__
        epoll_ctl(efd, EPOLL_CTL_DEL, this->fd, nullptr);
#endif
#if __APPLE__
        struct kevent event[2];
        EV_SET(&event[0], this->fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&event[1], this->fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(efd, event, 2, nullptr, 0, nullptr);
#endif
        close(this->fd);
        events = RW_EVENT::NONE;
    }
    this->fd = fd;
    LOGD(DEVENT, "%p set fd: %d\n", this, fd);
    SetSocketUnblock(fd);
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
        struct kevent event[3];
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
        //EV_SET(&event[count++], fd, EVFILT_EXCEPT, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void*)(intptr_t)this);
        int ret = kevent(efd, event, count, NULL, 0, NULL);
        if(ret < 0){
            LOGE("kevent failed %d:%s\n", efd, strerror(errno));
            return;
        }
#endif
#ifndef NDEBUG
        if(events != this->events) {
            assert(int(events) <= 3);
            LOGD(DEVENT, "modify event %d: %s --> %s\n", fd, events_string[int(this->events)], events_string[int(events)]);
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

int event_loop(uint32_t timeout_ms){
    int c;
#if __linux__
    struct epoll_event events[200];
    if ((c = epoll_wait(efd, events, 200, timeout_ms)) <= 0) {
        if (c != 0 && errno != EINTR) {
            LOGE("epoll_wait: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    for (int i = 0; i < c; ++i) {
        Ep *ep = (Ep *)events[i].data.ptr;
        LOGD(DEVENT, "handle event %d: %s\n", ep->getFd(), events_string[int(convertEpoll(events[i].events))]);
        (ep->*ep->handleEvent)(convertEpoll(events[i].events));
    }
    return 0;
#endif
#if __APPLE__
    struct kevent events[200];
    struct timespec timeout{timeout_ms/1000, (timeout_ms%1000)*1000000};
    if((c = kevent(efd, NULL, 0, events, 200, &timeout)) <= 0){
        if (c != 0 && errno != EINTR) {
            LOGE("kevent: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    std::map<Ep*, RW_EVENT> events_merged;
    for(int i = 0; i < c; ++i){
        LOGD(DEVENT, "handle event %lu: %s\n", events[i].ident, events_string[int(convertKevent(events[i]))]);
        Ep *ep = (Ep*)events[i].udata;
        if(events_merged.count(ep)){
            events_merged[ep] = events_merged[ep] | convertKevent(events[i]);
        }else{
            events_merged[ep] = convertKevent(events[i]);
        }
    }
    for(const auto& i: events_merged){
        (i.first->*i.first->handleEvent)(i.second);
    }
    return 0;
#endif
    return -1;
}

