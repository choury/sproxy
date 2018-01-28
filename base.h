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
    virtual void dump_stat() = 0;
    virtual ~Server();
};

class Peer:public Server {
protected:
    virtual void deleteLater(uint32_t errcode);
public:
    
    virtual int32_t bufleft(void* index) = 0;
    virtual ssize_t Send(const void *buff, size_t size, void* index) final;
    virtual ssize_t Send(void* buff, size_t size, void* index) = 0;
    //return wheather remain the connection, false means break the connection
    virtual bool finish(uint32_t flags, void* info) = 0;

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

class RBuffer {
    char content[BUF_LEN + DOMAINLIMIT];
    uint16_t len = 0;
public:
    size_t left();
    size_t length();
    size_t add(size_t l);
    size_t sub(size_t l);
    char* start();
    char* end();
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
    RBuffer rb;
    WBuffer wb;
    uint16_t port = 0;
    Protocol protocol;
    char     hostname[DOMAINLIMIT] = {0};
    std::function<void(int ret, int code)> errorCB = nullptr;
    std::function<void(size_t len)> readCB = nullptr;
    std::function<void(size_t len)> writeCB = nullptr;
    std::function<void()> connectCB = nullptr;
    std::function<void()> closeCB = nullptr;
    std::queue<sockaddr_un> addrs;
    virtual void waitconnectHE(int events);
    virtual void defaultHE(int events);
    virtual void closeHE(int events);
    void connect();
    void reconnect(int error);
    int checksocket();
    static void Dnscallback(RWer* rwer, const char *hostname, std::list<sockaddr_un> addrs);
    static int  con_timeout(RWer* rwer);

    virtual ssize_t Read(void* buff, size_t len);
    virtual ssize_t Write(const void* buff, size_t len);
public:
    RWer(int fd, std::function<void(int ret, int code)> errorCB);
    RWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB);
    virtual ~RWer();
    void SetErrorCB(std::function<void(int ret, int code)> func);
    void SetReadCB(std::function<void(size_t len)> func);
    void SetWriteCB(std::function<void(size_t len)> func);
    void SetConnectCB(std::function<void()> func);

    virtual void TrigRead();
    virtual void Close(std::function<void()> func);
    virtual void Shutdown();

    //for read buffer
    size_t rlength();
    const char *data();
    void consume(size_t l);

    //for write buffer
    size_t wlength();
    std::list<write_block>::insert_iterator buffer_head();
    std::list<write_block>::insert_iterator buffer_end();
    virtual ssize_t buffer_insert(std::list<write_block>::insert_iterator where, const void* buff, size_t len);
    virtual ssize_t buffer_insert(std::list<write_block>::insert_iterator where, void* buff, size_t len);
    virtual void Clear(bool freebuffer);
};

void flushproxy2();
void releaseall();
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);

#endif
