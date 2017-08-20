#ifndef BASE_H__
#define BASE_H__

#include "common.h"
#include <queue>
#include <functional>

class Con {
protected:
    int fd = 0;
    uint32_t events = 0;
    void updateEpoll(uint32_t events);
    virtual void discard();
public:
    explicit Con(int fd);
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual void dump_stat() = 0;
    virtual ~Con();
};

class Server:public Con{
protected:
    virtual void defaultHE(uint32_t events)=0;
public:
    explicit Server(int fd);
};


class Peer:public Con{
protected:
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write(const void *buff, size_t size);
    
    virtual void closeHE(uint32_t events);
    virtual void deleteLater(uint32_t errcode);
public:
    virtual ~Peer();
    

    virtual int32_t bufleft(void* index) = 0;
    virtual ssize_t Send(const void *buff, size_t size, void* index) final;
    virtual ssize_t Send(void* buff, size_t size, void* index) = 0;
    //return false means break the connection
    virtual bool finish(uint32_t flags, void* info) = 0;

    virtual void writedcb(void* index);
};



class Buffer{
    std::queue<write_block> write_queue;
public:
    ~Buffer();
    size_t  length = 0;
    void push(void *buff, size_t size);
    ssize_t  Write(std::function<ssize_t(const void*, size_t)> write_func);
};

void flushproxy2();
void releaseall();
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);

#endif
