#ifndef NETIO_H__
#define NETIO_H__
#include "rwer.h"
#include "common/common.h"
#include "prot/dns/resolver.h"

#include <queue>

class RBuffer {
    char content[BUF_LEN*2];
    uint16_t len = 0;
public:
    size_t left();
    size_t length();
    size_t add(size_t l);
    const char* data();
    size_t consume(const char*, size_t l);
    char* end();
};

class CBuffer {
    char content[BUF_LEN*2];
    uint32_t begin_pos = 0;
    uint32_t end_pos = 0;
public:
    size_t left();
    size_t length();
    void add(size_t l);
    const char* data();
    void consume(const char* data, size_t l);
    char* end();
};

class SocketRWer: public RWer{
protected:
    uint16_t port = 0;
    Protocol protocol;
    char     hostname[DOMAINLIMIT] = {0};
    std::queue<sockaddr_storage> addrs;
    int      retry = 3;
    Job*     con_failed_job = nullptr;
    Resolver*  resolver = nullptr;
    virtual void waitconnectHE(RW_EVENT events);
    static void Dnscallback(void* param, std::list<sockaddr_storage> addrs);
    void connect();

    void connectFailed(int error);
    virtual void Connected(const sockaddr_storage&) override;

    virtual ssize_t Write(const void* buff, size_t len) override;
public:
    SocketRWer(int fd, const sockaddr_storage* peer, std::function<void(int ret, int code)> errorCB);
    SocketRWer(const char* hostname, uint16_t port, Protocol protocol,
           std::function<void(int ret, int code)> errorCB,
           std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~SocketRWer() override;
    virtual const char* getPeer() override;
};

class StreamRWer: public SocketRWer{
protected:
    CBuffer rb;
    virtual ssize_t Read(void* buff, size_t len);
    virtual void ReadData() override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength() override;
    virtual size_t rleft() override;
    virtual const char *rdata() override;
    virtual void consume(const char*, size_t l) override;
};

class PacketRWer: public SocketRWer{
protected:
    RBuffer rb;
    virtual ssize_t Read(void* buff, size_t len);
    virtual void ReadData() override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength() override;
    virtual size_t rleft() override;
    virtual const char *rdata() override;
    virtual void consume(const char*, size_t l) override;
};


#endif
