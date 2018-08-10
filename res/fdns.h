#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"
#include <map>

struct FDnsStatus{
    Requester* req_ptr;
    void*      req_index;
    uint32_t   dns_id;
};

class FDns: public Responser{
    std::map<int, FDnsStatus> statusmap;
    uint32_t req_id = 1;

    virtual void writedcb(void* index) override;
    virtual void deleteLater(uint32_t errcode) override;
public:
    FDns();
    ~FDns();
    virtual void* request(HttpReqHeader* req) override;
    virtual ssize_t Send(void *buff, size_t size, void* index)override;
    static void ResponseCb(uint32_t id, const char *buff, size_t size);

    virtual int32_t bufleft(void* index)override;
    virtual void finish(uint32_t flags, void* index)override;

    virtual void dump_stat(Dumper dp, void* param) override;
    static FDns* getfdns();
    static std::string getRdns(const struct in_addr* addr);
    static in_addr getInet(std::string hostname);
};

#endif
