#ifndef RESOLVER_H__
#define RESOLVER_H__

#include "common/base.h"

#include <list>
#include <string>
#include <netinet/in.h>



class RawResolver: public Ep{
    Job reply = nullptr;
    std::function<void(const char*, size_t, RawResolver*)> cb = nullptr;
    void readHE(RW_EVENT events);
public:
    explicit RawResolver(int fd, const char* host,
                      int type, std::function<void(const char*, size_t, RawResolver*)>  rawcb);
    virtual ~RawResolver() override;
};

struct Dns_Rcd{
    std::list<sockaddr_storage> addrs;
    time_t get_time;
    uint32_t ttl;
};

class HostResolver: public Ep{
    Job  reply = nullptr;
#define GETARES    1
#define GETAAAARES 2
#define GETERROR   4
    uint32_t flags = 0;
    std::function<void(int, HostResolver*)> cb = nullptr;
    void readHE(RW_EVENT events);
public:
    char host[DOMAINLIMIT];
    Dns_Rcd  rcd;
    explicit HostResolver(int fd, const char* host, std::function<void(int, HostResolver*)> addrcb);
    virtual ~HostResolver() override;
};


typedef void (*DNSCB)(std::shared_ptr<void>, int error, std::list<sockaddr_storage> addrs);
typedef void (*DNSRAWCB)(std::shared_ptr<void>, const char *buff, size_t size);

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param);
void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param);
void RcdBlock(const char *hostname, const sockaddr_storage &addr);
void dump_dns(Dumper dp, void* param);

#endif
