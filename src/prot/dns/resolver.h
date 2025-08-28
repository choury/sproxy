#ifndef RESOLVER_H__
#define RESOLVER_H__

#include "common/common.h"
#include "misc/job.h"
#include "prot/ep.h"

#include <list>
#include <string>
#include <netinet/in.h>


#define DNS_TIMEOUT      0xf0

class ResolverBase{
protected:
    std::function<void(const char*, size_t)> dnscb = nullptr;
public:
    virtual ~ResolverBase() {}
    virtual int query(const char* host, int type, std::function<void(const char*, size_t)>  cb) = 0;
    virtual int query(const void* data, size_t len, std::function<void(const char*, size_t)>  cb) = 0;
};

class MemRWer;
class HttpReqHeader;
struct IMemRWerCallback;
class HttpResolver: public ResolverBase {
    Job reply = nullptr;
    struct Status {
        std::shared_ptr<HttpReqHeader>   req;
        std::shared_ptr<MemRWer>          rw;
        std::shared_ptr<IMemRWerCallback> cb;
        std::string data;
    }status{};
    std::function<void(const char*, size_t)> dnscb = nullptr;
public:
    explicit HttpResolver(const Destination& server);
    virtual ~HttpResolver() override;

    virtual int query(const char* host, int type, std::function<void(const char*, size_t)> cb) override;
    virtual int query(const void* data, size_t len, std::function<void(const char*, size_t)> cb) override;
};

class RawResolver: public Ep, public ResolverBase{
    Job reply = nullptr;
    std::function<void(const char*, size_t)> cb = nullptr;
    void readHE(RW_EVENT events);
public:
    explicit RawResolver(const sockaddr_storage& server);
    virtual ~RawResolver() override;

    virtual int query(const char* host, int type, std::function<void(const char*, size_t)>  cb) override;
    virtual int query(const void* data, size_t len, std::function<void(const char*, size_t)>  cb) override;
};

struct Dns_Rcd{
    std::list<sockaddr_storage> addrs;
    time_t get_time;
    uint32_t ttl;
};

class HostResolver {
#define GETARES    1
#define GETAAAARES 2
#define GETERROR   4
    uint32_t flags = 0;
    std::function<void(int)> cb = nullptr;
    ResolverBase* AResolver = nullptr;
    ResolverBase* AAAAResolver = nullptr;
public:
    char host[DOMAINLIMIT];
    Dns_Rcd  rcd;
    explicit HostResolver(const sockaddr_storage& server);
    explicit HostResolver(const Destination& server);
    int query(const char* host, std::function<void(int)> addrcb);
    ~HostResolver();
};

typedef void (*DNSCB)(std::shared_ptr<void>, int error,const std::list<sockaddr_storage>& addrs, int ttl);
typedef void (*DNSRAWCB)(std::shared_ptr<void>, const char *buff, size_t size);

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param, bool raw = false);
void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param);
void query_raw(const void* data, size_t len, DNSRAWCB func, std::shared_ptr<void> param);
void RcdBlock(const char *hostname, const sockaddr_storage &addr);
void dump_dns(Dumper dp, void* param);

#endif
