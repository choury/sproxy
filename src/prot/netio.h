#ifndef NETIO_H__
#define NETIO_H__
#include "rwer.h"
#include "common/common.h"
#include "prot/dns/resolver.h"

#include <queue>

class RBuffer {
    char content[BUF_LEN*2];
    size_t len = 0;
public:
    //for put
    size_t left();
    char* end();
    size_t add(size_t l);
    ssize_t put(const void* data, size_t size);

    //for get
    size_t length();
    size_t cap();
    const char* data();
    size_t consume(size_t l);
};

class CBuffer {
    char content[BUF_LEN*2];
    uint64_t offset = 0;
    size_t len = 0;
public:
    //for put
    size_t left();
    char* end();
    void add(size_t l);
    ssize_t put(const void* data, size_t size);
    uint64_t Offset(){
        return offset;
    };

    //for get
    size_t length();
    size_t cap();
    size_t get(char* buff, size_t len);
    void consume(size_t l);
};

class SocketRWer: public RWer{
protected:
    uint16_t port = 0;
    Protocol protocol;
    char     hostname[DOMAINLIMIT] = {0};
    std::queue<sockaddr_storage> addrs;
    void connect();
    Job*     con_failed_job = nullptr;
    // connectFailed should only be called with job con_failed_job,
    // there's always an extra job somewhere if you invoke it directly.
    void connectFailed(int error);
    static void Dnscallback(std::weak_ptr<void> param, int error, std::list<sockaddr_storage> addrs);

    virtual void waitconnectHE(RW_EVENT events);
    virtual void Connected(const sockaddr_storage&) override;
    virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
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
    virtual void ConsumeRData() override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength() override;
};

class PacketRWer: public SocketRWer{
protected:
    RBuffer rb;
    virtual ssize_t Read(void* buff, size_t len);
    virtual void ReadData() override;
    virtual void ConsumeRData() override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength() override;
};


#endif
