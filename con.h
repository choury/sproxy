#ifndef CON_H__
#define CON_H__

#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/epoll.h>

extern int efd;

class Con {
protected:
    int fd = 0;
    uint32_t events = 0;
    void updateEpoll(uint32_t events){
        if (fd > 0 && events != this->events) {
            if(events == 0){
               epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
            }else{
                struct epoll_event event;
                event.data.ptr = this;
                event.events = events;
                if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && 
                    errno == ENOENT)
                {
                    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
                }
            }
            this->events = events;
        }
    }
public:
    Con(int fd):fd(fd){}
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual ~Con(){
        if(fd > 0){
            updateEpoll(0);
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
