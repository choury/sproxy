#ifndef NETIO_H__
#define NETIO_H__
#include "common/common.h"
#include "hook/reflect.h"
#include "rwer.h"
#include "misc/job.h"

#include <queue>
#include <string>

struct Host_Result; //dns/resolver.h

struct ISocketCallback: public IRWerCallback {
    std::function<void(const sockaddr_storage&, uint32_t resolved_time)> connectCB = [](const sockaddr_storage&, uint32_t){};

    template<typename F>
    std::shared_ptr<ISocketCallback> onConnect(F&& func) {
        connectCB = std::forward<F>(func);
        return std::dynamic_pointer_cast<ISocketCallback>(shared_from_this());
    }

    static std::shared_ptr<ISocketCallback> create() {
        return std::make_shared<ISocketCallback>();
    }
};

class SocketRWer: public RWer{
protected:
    uint16_t port = 0;
    Protocol protocol = Protocol::NONE;
    char     hostname[DOMAINLIMIT] = {0};
    uint32_t resolved_time = 0;
    std::unique_ptr<sockaddr_storage> assign_src;
    std::queue<sockaddr_storage> addrs;
    void connect();
    Job     dns_job = nullptr;
    Job     con_failed_job = nullptr;
    std::string ech_config;    //DNS HTTPS RR中获取的ECHConfigList，供TLS握手前使用
    //std::function<void(const sockaddr_storage&, uint32_t resolved_time)> connectCB = [](const sockaddr_storage&, uint32_t){};
    // connectFailed should only be called with job con_failed_job,
    // there's always an extra job somewhere if you invoke it directly.
    void connectFailed(int error);
    void connected(const sockaddr_storage& addr);
    static void Dnscallback(const Host_Result& result);

    virtual void waitconnectHE(RW_EVENT events);
    //virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
public:
    SocketRWer(int fd, const sockaddr_storage* src, std::shared_ptr<IRWerCallback> cb);
    SocketRWer(const Destination& dest, std::shared_ptr<IRWerCallback> cb);
    SocketRWer(const sockaddr_storage& addr, Protocol protocol, std::shared_ptr<IRWerCallback> cb);
    //virtual void SetConnectCB(std::function<void(const sockaddr_storage&, uint32_t resolved_time)> connectCB);
    virtual void SetCallback(std::shared_ptr<IRWerCallback> cb) override;
    virtual ~SocketRWer() override;
    virtual Destination getSrc() const override;
    virtual Destination getDst() const override;
    virtual void dump_status(Dumper dp, void* param) override;
    void reflect(IVisitor& v) override {
        RWer::reflect(v);
        reflect_all(port, protocol, hostname, resolved_time);
        if (assign_src) {
            reflect_named("assign_src", *assign_src);
        }
    }
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
        return sizeof(*this) + rb.mem_usage() + wbuff.mem_usage();
    }
    void reflect(IVisitor& v) override {
        SocketRWer::reflect(v);
        reflect_all(rb);
    }
};

class PacketRWer: public SocketRWer{
protected:
    char rb[BUF_LEN];
    std::deque<Buffer> wbuff;
    size_t             wlen;
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

    virtual void Send(Buffer&& bb) override;
    void reflect(IVisitor& v) override {
        SocketRWer::reflect(v);
        reflect_all(wlen, rb, wbuff);
    }
};


#endif
