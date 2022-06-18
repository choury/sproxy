#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"
#include "prot/dns/resolver.h"
#include "prot/dns/dns.h"
#include <map>

struct FDnsStatus{
    std::shared_ptr<HttpReq>   req;
    std::shared_ptr<HttpRes>   res;
    std::shared_ptr<Dns_Query> que;
};


class FDns: public Responser{
    std::map<uint32_t, FDnsStatus> statusmap;

    void Recv(Buffer&& bb);
    static void RawCb(std::shared_ptr<void> param, const char *buff, size_t size);
    static void DnsCb(std::shared_ptr<void> param, int error, std::list<sockaddr_storage> addrs);
public:
    FDns();
    virtual ~FDns() override;
    static FDns* GetInstance();
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

std::string getRdns(const sockaddr_storage& addr);
#endif
