#ifndef RESOLVER_H__
#define RESOLVER_H__

#include "common/base.h"

#include <list>
#include <string>
#include <netinet/in.h>



class RawResolver: public Ep{
    Job* reply = nullptr;
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
    Job*  reply = nullptr;
#define GETARES    1
#define GETAAAARES 2
#define GETERROR   4
    uint32_t flags = 0;
    Dns_Rcd  rcd;
    std::function<void(int, std::list<sockaddr_storage>, HostResolver*)> cb = nullptr;
    void readHE(RW_EVENT events);
public:
    char host[DOMAINLIMIT];
    explicit HostResolver(int fd, const char* host,
                      std::function<void(int, std::list<sockaddr_storage>, HostResolver*)>  addrcb);
    virtual ~HostResolver() override;
};


typedef void (*DNSCB)(std::weak_ptr<void>, int error, std::list<sockaddr_storage> addrs);
typedef void (*DNSRAWCB)(std::weak_ptr<void>, const char *buff, size_t size);

void query_host(const char* host, DNSCB func, std::weak_ptr<void> param);
void query_dns(const char* host, int type, DNSRAWCB func, std::weak_ptr<void> param);
void RcdBlock(const char *hostname, const sockaddr_storage &addr);


#endif
