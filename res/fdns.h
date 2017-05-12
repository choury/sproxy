#ifndef FDNS_H__
#define FDNS_H__

//fake dns

#include "responser.h"
#include "prot/binmap.h"
#include <map>

extern binmap<uint32_t, std::string> fdns_records;

struct FDnsStatus{
    Requester* req_ptr;
    void*      req_index;
    uint32_t   dns_id;
};

class FDns: public Responser{
    std::map<int, FDnsStatus> statusmap;
    uint32_t req_id = 1;
    in_addr_t fake_ip;
public:
    FDns();
    virtual void* request(HttpReqHeader&& req) override;
    virtual ssize_t Write(void *buff, size_t size, void* index)override;
    static void ResponseCb(uint32_t id, const char *buff, size_t size);
    virtual void clean(uint32_t errcode, void* index)override;
    static FDns* getfdns();
};

#endif
