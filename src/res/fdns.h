#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"

struct Dns_Query;
class FDns: public Responser{
    struct FDnsStatus{
        std::shared_ptr<RWer>          rw;
        std::shared_ptr<IRWerCallback> cb;
        std::map<uint16_t, std::shared_ptr<Dns_Query>> quemap;
    };
    std::map<uint64_t, FDnsStatus> statusmap;

    void Recv(Buffer&& bb);
    static void RawCb(std::shared_ptr<void> param, const char *buff, size_t size);
    static void DnsCb(std::shared_ptr<void> param, int error, const std::list<sockaddr_storage>& addrs, int ttl);
    FDns();
    virtual ~FDns() override;
public:
    static FDns* GetInstance();
    virtual void request(std::shared_ptr<HttpReqHeader>, std::shared_ptr<MemRWer>, Requester*) override {};
    void query(uint64_t id, std::shared_ptr<RWer> rwer);
    void query(Buffer&& bb, std::shared_ptr<RWer> rwer);
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

bool isFakeIp(const sockaddr_storage& addr);
std::string getRdns(const sockaddr_storage& addr);
std::string getRdnsWithPort(const sockaddr_storage& addr);
#endif
