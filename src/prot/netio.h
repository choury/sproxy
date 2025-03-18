#ifndef NETIO_H__
#define NETIO_H__
#include "rwer.h"
#include "common/common.h"
#include "prot/dns/resolver.h"

#include <queue>


class SocketRWer: public RWer{
protected:
    uint16_t port = 0;
    Protocol protocol = Protocol::NONE;
    char     hostname[DOMAINLIMIT] = {0};
    std::queue<sockaddr_storage> addrs;
    void connect();
    Job     dns_job = nullptr;
    Job     con_failed_job = nullptr;
    std::function<void(const sockaddr_storage&)> connectCB = [](const sockaddr_storage&){};
    // connectFailed should only be called with job con_failed_job,
    // there's always an extra job somewhere if you invoke it directly.
    void connectFailed(int error);
    void connected(const sockaddr_storage& addr);
    static void Dnscallback(std::shared_ptr<void> param, int error, const std::list<sockaddr_storage>& addrs, int ttl);

    virtual void waitconnectHE(RW_EVENT events);
    //virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
    virtual bool IsConnected();
public:
    SocketRWer(int fd, const sockaddr_storage* src, std::function<void(int ret, int code)> errorCB);
    SocketRWer(const char* hostname, uint16_t port, Protocol protocol,
           std::function<void(int ret, int code)> errorCB);
    virtual void SetConnectCB(std::function<void(const sockaddr_storage&)> connectCB);
    virtual ~SocketRWer() override;
    virtual Destination getSrc() const override;
    virtual Destination getDst() const override;
    virtual void dump_status(Dumper dp, void* param) override;
};

class StreamRWer: public SocketRWer{
protected:
    CBuffer rb;
    //virtual ssize_t Read(void* buff, size_t len);
    virtual void ReadData() override;
    virtual void ConsumeRData(uint64_t id) override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength(uint64_t id) override;
    virtual size_t mem_usage() override {
        return sizeof(*this) + (rb.cap() + rb.length()) + wlen;
    }
};

class PacketRWer: public SocketRWer{
protected:
    char rb[BUF_LEN];
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual void ReadData() override;
    virtual void ConsumeRData(uint64_t id) override;
public:
    using SocketRWer::SocketRWer;

    //for read buffer
    virtual size_t rlength(uint64_t id) override;
    virtual size_t mem_usage() override {
        return sizeof(*this) + wlen;
    }
};


#endif
