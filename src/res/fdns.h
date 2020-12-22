#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"
#include <map>

struct FDnsStatus{
    HttpReq*   req;
    HttpRes*   res;
};

class FDns: public Responser{
    std::map<uint64_t, FDnsStatus> statusmap;

    void Send(uint32_t id, const void* buff, size_t size);
    virtual void deleteLater(uint32_t errcode) override;

    static void RawCb(void* param, const char *buff, size_t size);
    static void DnsCb(void* param, std::list<sockaddr_storage> addrs);
public:
    FDns();
    virtual ~FDns() override;
    virtual void request(HttpReq* req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;

    static FDns* getfdns();
};

std::string getRdns(const sockaddr_storage& addr);
#endif
