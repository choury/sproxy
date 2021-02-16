#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"
#include "prot/resolver.h"
#include "prot/dns.h"
#include <map>

class FDns;
struct FDnsStatus{
    FDns*      fdns;
    Dns_Query* que;
    Resolver*  resolver;
};

class FDns: public Responser{
    HttpReq*   req;
    HttpRes*   res;
    std::map<uint32_t, FDnsStatus*> statusmap;

    void Send(const void* buff, size_t size);
    void clean(FDnsStatus* status);
    virtual void deleteLater(uint32_t errcode) override;

    static void RawCb(void* param, const char *buff, size_t size);
    static void DnsCb(void* param, std::list<sockaddr_storage> addrs);
public:
    FDns();
    virtual ~FDns() override;
    virtual void request(HttpReq* req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

std::string getRdns(const sockaddr_storage& addr);
#endif
