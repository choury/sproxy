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
    Con(int fd);
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual void dump_stat() = 0;
    virtual ~Con();
};

class Server:public Con{
protected:
    virtual void defaultHE(uint32_t events)=0;
public:
    Server(int fd);
};


class Peer:public Con{
protected:
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write(const void *buff, size_t size);
    
    virtual void closeHE(uint32_t events);
public:
    virtual ~Peer();
    virtual void deleteLater(uint32_t errcode);
    

    virtual int32_t bufleft(void* index) = 0;
    virtual ssize_t Send(const void *buff, size_t size, void* index) final;
    virtual ssize_t Send(void* buff, size_t size, void* index) = 0;
    virtual void finish(uint32_t errcode, void* info) = 0;

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
