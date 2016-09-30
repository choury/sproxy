#ifndef CON_H__
#define CON_H__

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <assert.h>

extern int efd;

class Con {
protected:
    int fd = 0;
    void updateEpoll(uint32_t events){
        if (fd > 0) {
            int __attribute__((unused)) ret = 0;
            if(events == 0){
               ret = epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
               assert(ret == 0);
            }else{
                struct epoll_event event;
                event.data.ptr = this;
                event.events = events;
                ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                assert(ret == 0 || errno == ENOENT);
                if (ret && errno == ENOENT)
                {
                    int __attribute__((unused)) ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
                    assert(ret == 0);
                }
            }
        }
    }
public:
    Con(int fd):fd(fd){}
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual void discard(){
        fd = 0;
    }
    virtual ~Con(){
        if(fd > 0){
            close(fd);
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
