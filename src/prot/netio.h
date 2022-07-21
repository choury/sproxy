#ifndef NETIO_H__
#define NETIO_H__
#include "rwer.h"
#include "common/common.h"
#include "prot/dns/resolver.h"

#include <queue>


class SocketRWer: public RWer{
protected:
    uint16_t port = 0;
    Protocol protocol;
    char     hostname[DOMAINLIMIT] = {0};
    std::queue<sockaddr_storage> addrs;
    void connect();
    Job*     con_failed_job = nullptr;
    std::function<void(const sockaddr_storage&)> connectCB;
    // connectFailed should only be called with job con_failed_job,
    // there's always an extra job somewhere if you invoke it directly.
    void connectFailed(int error);
    void connected(const sockaddr_storage& addr);
    static void Dnscallback(std::shared_ptr<void> param, int error, std::list<sockaddr_storage> addrs);

    virtual void waitconnectHE(RW_EVENT events);
    virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
public:
    SocketRWer(int fd, const sockaddr_storage* peer, std::function<void(int ret, int code)> errorCB);
    SocketRWer(const char* hostname, uint16_t port, Protocol protocol,
           std::function<void(int ret, int code)> errorCB,
           std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~SocketRWer() override;
    virtual const char* getPeer() override;
    virtual void dump_status(Dumper dp, void* param) override;
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
    char rb[BUF_LEN * 2];
    size_t rlen = 0;
    virtual ssize_t Read(void* buff, size_t len);
    virtual void ReadData() override;
    virtual void ConsumeRData() override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength() override;
};


#endif
