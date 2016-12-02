#ifndef CON_H__
#define CON_H__

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <assert.h>


extern int efd;

#ifndef NDEBUG
#include <map>
#include "common.h"
class Con;
static  std::map<int, Con *> epolls;
static const char *epoll_string[]= {
    "NULL",
    "EPOLLIN",
    "EPOLLPRI",
    "EPOLLIN|EPOLLPRI",
    "EPOLLOUT",
    "EPOLLOUT|EPOLLIN",
    "EPOLLOUT|EPOLLPRI",
    "EPOLLOUT|EPOLLIN|EPOLLPRI",
};
#endif

class Con {
protected:
    int fd = 0;
    uint32_t events = 0;
    void updateEpoll(uint32_t events) {
        int __attribute__((unused)) ret;
        if (fd > 0) {
            if(events == 0){
#ifndef NDEBUG
                LOGD(DEPOLL, "del %d: %p\n", fd, this);
                assert(epolls[fd] == this);
                epolls.erase(fd);
#endif
                ret =  epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
                assert(ret == 0 || fprintf(stderr, "epoll_ctl del failed:%m\n"));
            }else{
                struct epoll_event event;
                event.data.ptr = this;
                event.events = events;
                ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                assert(ret == 0 || errno == ENOENT || fprintf(stderr, "epoll_ctl mod failed:%m\n")==0);
                if (ret && errno == ENOENT)
                {
                    ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
                    assert(ret == 0 || fprintf(stderr, "epoll_ctl add failed:%m\n")==0);
#ifndef NDEBUG
                    LOGD(DEPOLL, "add %d: %p\n", fd, this);
                    assert(epolls.count(fd) == 0);
                    epolls[fd]=this;
#endif
                }else{
#ifndef NDEBUG
                    if(epolls[fd] != this) {
                        LOGD(DEPOLL, "change %d: %p --> %p\n", fd, epolls[fd], this);
                    }
                    assert(epolls.count(fd));
                    epolls[fd]=this;
#endif
                }
#ifndef NDEBUG
                if(events != this->events) {
                    assert(events <= 7);
                    LOGD(DEPOLL, "modify %d: %s --> %s\n", fd, epoll_string[this->events], epoll_string[events]);
                }
#endif
                this->events = events;
            }
        }
    }
    virtual void discard(){
        fd = 0;
        events = 0;
    }
public:
    Con(int fd):fd(fd){}
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual ~Con(){
        if(fd > 0){
            updateEpoll(0);
            int __attribute__((unused)) ret = close(fd);
            assert(ret == 0 || fprintf(stderr, "close error:%m\n") == 0);
        }
    }
};

class Server:public Con{
protected:
    virtual void defaultHE(uint32_t events)=0;
public:
    Server(int fd):Con(fd){
        updateEpoll(EPOLLIN);
        handleEvent = (void (Con::*)(uint32_t))&Server::defaultHE;
    }
};

#endif
