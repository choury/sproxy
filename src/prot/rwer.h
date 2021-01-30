#ifndef RWER_H__
#define RWER_H__

#include "misc/job.h"

#include <sys/types.h>
#include <sys/socket.h>

#include <memory>
#include <list>
#include <functional>


#ifndef insert_iterator
#ifdef HAVE_CONST_ITERATOR_BUG
#define insert_iterator iterator
#else
#define insert_iterator const_iterator
#endif
#endif

struct write_block{
    void* const buff;
    size_t len;
    size_t offset;
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
    std::list<write_block>::iterator push(std::list<write_block>::insert_iterator i, const write_block& wb);
    ssize_t  Write(std::function<ssize_t(const void*, size_t)> write_func);
};

enum class RW_EVENT{
    NONE = 0,
    READ = 1,
    WRITE = 2,
    READWRITE = READ | WRITE,
    READEOF = 4,
    ERROR = 8,
};

RW_EVENT operator&(RW_EVENT a, RW_EVENT b);
RW_EVENT operator|(RW_EVENT a, RW_EVENT b);
RW_EVENT operator~(RW_EVENT a);
bool operator!(RW_EVENT a);
extern const char *events_string[];

#ifdef __linux__
RW_EVENT convertEpoll(uint32_t events);
#endif

#ifdef  __APPLE__
RW_EVENT convertKevent(const struct kevent& event);
#endif

class Ep{
    int fd;
protected:
    RW_EVENT events = RW_EVENT::NONE;
    void setFd(int fd);
    int getFd();
public:
    explicit Ep(int fd);
    virtual ~Ep();
    void setEvents(RW_EVENT events);
    void addEvents(RW_EVENT events);
    void delEvents(RW_EVENT events);
    RW_EVENT getEvents();
    int checkSocket(const char* msg);
    void (Ep::*handleEvent)(RW_EVENT events) = nullptr;
};


using std::placeholders::_1;
using std::placeholders::_2;

enum class RWerStats{
    Idle = 0,
    Resolving,
    Connecting,
    Connected,
    SslAccepting,
    SslConnecting,
    ReadEOF,
    Shutdown,
    Error,
};

class RWer: public Ep, public job_handler{
protected:
#define RWER_READING  1u
#define RWER_SENDING  2u
#define RWER_CLOSING  4u
    uint32_t   flags = 0;
    RWerStats  stats = RWerStats::Idle;
    WBuffer    wbuff;
    std::function<void(size_t len)> readCB;
    std::function<void(size_t len)> writeCB;
    std::function<void(const sockaddr_storage&)> connectCB;
    std::function<void(int ret, int code)> errorCB;
    std::function<void()> closeCB;

    virtual ssize_t Write(const void* buff, size_t len) = 0;
    virtual void SendData();
    virtual void ReadData() = 0;
    virtual void defaultHE(RW_EVENT events);
    virtual void closeHE(RW_EVENT events);
    virtual void Connected(const sockaddr_storage&);
    virtual void ErrorHE(int ret, int code);
public:
    explicit RWer(int fd, std::function<void(int ret, int code)> errorCB);
    explicit RWer(std::function<void(int ret, int code)> errorCB,
                  std::function<void(const sockaddr_storage&)> connectCB);
    virtual void SetErrorCB(std::function<void(int ret, int code)> func);
    virtual void SetReadCB(std::function<void(size_t len)> func);
    virtual void SetWriteCB(std::function<void(size_t len)> func);

    virtual bool supportReconnect();
    virtual void Reconnect();
    virtual void Close(std::function<void()> func);
    virtual void EatReadData();
    virtual void Shutdown();
    RWerStats getStats(){return stats;}
    virtual const char* getPeer() {return "raw-rwer";}
    virtual const char* getDest() {return getPeer();}

    //for read buffer
    virtual size_t rlength() = 0;
    virtual size_t rleft() = 0;
    virtual const char *rdata() = 0;
    virtual void consume(const char* data, size_t l) = 0;

    //for write buffer
    virtual size_t wlength();
    virtual std::list<write_block>::insert_iterator buffer_head();
    virtual std::list<write_block>::insert_iterator buffer_end();
    virtual std::list<write_block>::insert_iterator
    buffer_insert(std::list<write_block>::insert_iterator where, const write_block& wb);
    //virtual void Clear(bool freebuffer);
};

class NullRWer: public RWer{
public:
    explicit NullRWer();
    virtual ssize_t Write(const void *buff, size_t len) override;
    virtual void ReadData() override;
    virtual size_t rleft() override;
    virtual size_t rlength() override;
    virtual size_t wlength() override;
    virtual const char * rdata() override;
    virtual void consume(const char* data, size_t l) override;
    virtual const char* getPeer() override {return "null-rwer";}
};

class FullRWer: public RWer{
protected:
#ifndef __linux__
    int pairfd = -1;
#endif
    virtual ssize_t Write(const void* buff, size_t len) override;
    virtual void ReadData() override;
    virtual void closeHE(RW_EVENT events) override;
public:
    explicit FullRWer(std::function<void(int ret, int code)> errorCB);
    ~FullRWer() override;

    virtual size_t rlength() override;
    virtual size_t rleft() override;
    virtual const char *rdata() override;
    virtual void consume(const char* data, size_t l) override;
    virtual const char* getPeer() override {return "full-rwer";}
};

#endif
