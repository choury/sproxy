#ifndef RESOLVER_H__
#define RESOLVER_H__

#include "base.h"

#include <list>
#include <string>
#include <netinet/in.h>

struct Dns_Rcd{
    std::list<sockaddr_storage> addrs;
    time_t get_time;
    uint32_t ttl;
};


class Resolver: public Ep{
    sockaddr_storage addr;
    char     host[DOMAINLIMIT];
#define GETARES    1
#define GETAAAARES 2
    uint32_t flags = 0;
    Dns_Rcd  rcd;
    Job* reply = nullptr;
    std::function<void(std::list<sockaddr_storage>)> addrcb = nullptr;
    std::function<void(const char*, size_t)> rawcb = nullptr;
    void readHE(RW_EVENT events);
public:
    explicit Resolver(const char* host,
                      const std::function<void(std::list<sockaddr_storage>)>& addrcb,
                      const std::list<sockaddr_storage>& results);
    explicit Resolver(int fd, const char* host,
                      std::function<void(std::list<sockaddr_storage>)>  addrcb);
    explicit Resolver(int fd, const char* host,
                      int type, std::function<void(const char*, size_t)>  rawcb);
    virtual ~Resolver() override;
    void dump_stat(Dumper dp, void* param);
};


typedef void (*DNSCB)(void *, std::list<sockaddr_storage> addrs);
typedef void (*DNSRAWCB)(void *, const char *buff, size_t size);

Resolver* query_host(const char* host, DNSCB func, void* param);
Resolver* query_dns(const char* host, int type, DNSRAWCB func, void* param);
void RcdDown(const char *hostname, const sockaddr_storage &addr);


#endif
