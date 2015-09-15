#ifndef CON_H__
#define CON_H__

#include <stdint.h>
#include <sys/epoll.h>

extern int efd;

class Con {
public:
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual ~Con() {}
};

class Server:public Con{
protected:
    int fd;
    virtual void defaultHE(uint32_t events)=0;
public:
    Server(int fd):fd(fd){
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        handleEvent = (void (Con::*)(uint32_t))&Server::defaultHE;
    }
};

#endif
