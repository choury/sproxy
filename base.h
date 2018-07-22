#ifndef BASE_H__
#define BASE_H__

#include "common.h"
#include <queue>
#include <list>
#include <functional>

#include <string.h>

class RWer;

#ifndef insert_iterator
#ifdef HAVE_CONST_ITERATOR_BUG
#define insert_iterator iterator
#else
#define insert_iterator const_iterator
#endif
#endif

class Server {
protected:
    RWer* rwer = nullptr;
public:
    explicit Server();
    virtual void dump_stat(Dumper dp, void* param) = 0;
    virtual ~Server();
};

class Peer:public Server {
protected:
    virtual void deleteLater(uint32_t errcode);
public:
    virtual int32_t bufleft(void* index) = 0;
    virtual ssize_t Send(const void *buff, size_t size, void* index) final;
    virtual ssize_t Send(void* buff, size_t size, void* index) = 0;
    virtual void finish(uint32_t flags, void* info) = 0;

    virtual void writedcb(void* index);
};

class Ep{
protected:
    int fd;
    uint32_t events = 0;
public:
    Ep(int fd);
    virtual ~Ep();
    void setEpoll(uint32_t events);
    void addEpoll(uint32_t events);
    void delEpoll(uint32_t events);
    void (Ep::*handleEvent)(uint32_t events)=nullptr;
};


class WBuffer {
    std::list<write_block> write_queue;
    size_t  len = 0;
public:
    ~WBuffer();
    size_t length();
    void clear(bool freebuffer);
    std::list<write_block>::iterator start();
    std::list<write_block>::iterator end();
    std::list<write_block>::iterator push(std::list<write_block>::insert_iterator i, void *buff, size_t size);
    ssize_t  Write(std::function<ssize_t(const void*, size_t)> write_func);
};


using std::placeholders::_1;
using std::placeholders::_2;

class RWer: public Ep{
protected:
    WBuffer wb;
    std::function<void(int ret, int code)> errorCB = nullptr;
    std::function<void(size_t len)> readCB = nullptr;
    std::function<void(size_t len)> writeCB = nullptr;
    std::function<void()> connectCB = nullptr;
    std::function<void()> closeCB = nullptr;

    virtual ssize_t Write(const void* buff, size_t len) = 0;
    virtual void closeHE(uint32_t events);
public:
    RWer(std::function<void(int ret, int code)> errorCB, int fd = 0);
    virtual void SetErrorCB(std::function<void(int ret, int code)> func);
    virtual void SetReadCB(std::function<void(size_t len)> func);
    virtual void SetWriteCB(std::function<void(size_t len)> func);
    virtual void SetConnectCB(std::function<void()> func);

    virtual bool supportReconnect();
    virtual void Reconnect();
    virtual void TrigRead();
    virtual void Close(std::function<void()> func);
    virtual void Shutdown();

    //for read buffer
    virtual size_t rlength() = 0;
    virtual const char *data() = 0;
    virtual void consume(const char* data, size_t l) = 0;

    //for write buffer
    virtual size_t wlength();
    virtual std::list<write_block>::insert_iterator buffer_head();
    virtual std::list<write_block>::insert_iterator buffer_end();
    virtual std::list<write_block>::insert_iterator buffer_insert(std::list<write_block>::insert_iterator where, const void* buff, size_t len);
    virtual std::list<write_block>::insert_iterator buffer_insert(std::list<write_block>::insert_iterator where, void* buff, size_t len);
    virtual void Clear(bool freebuffer);
};


void flushproxy2(bool force);
void releaseall();
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);
void dump_stat(Dumper dp, void* param);

#endif
