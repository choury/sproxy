#ifndef BASE_H__
#define BASE_H__

#include "common.h"
#include <queue>

class Con {
protected:
    int fd = 0;
    uint32_t events = 0;
    void updateEpoll(uint32_t events);
    virtual void discard();
public:
    Con(int fd);
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual ~Con();
};

class Server:public Con{
protected:
    virtual void defaultHE(uint32_t events)=0;
public:
    Server(int fd);
};


#define WRITE_NOTHING     1
#define WRITE_INCOMP      2
#define WRITE_COMPLETE    3

struct write_block{
    void* buff;
    size_t len;
    size_t wlen;
};


class Peer:public Con{
    std::queue<write_block> write_queue;
    size_t  writelen = 0;
protected:
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write(const void *buff, size_t size);
    virtual ssize_t push_buff(void* buff, size_t size);
    virtual int Write_buff();
    
    virtual void closeHE(uint32_t events) = 0;
public:
    virtual ~Peer();
    
    virtual void clean(uint32_t errcode, void* info);
    
    virtual ssize_t Write(const void *buff, size_t size, void* index) final;
    virtual ssize_t Write(void* buff, size_t size, void* index);
    
    virtual void wait(void* index);
    virtual void writedcb(void* index);
    virtual int32_t bufleft(void* index);
};

void releaseall();
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);

#endif
