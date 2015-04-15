#ifndef DNS_H__
#define DNS_H__

#include <unistd.h>
#include <time.h>
#include <netinet/in.h>
#include <vector>

#include "con.h"
#include "net.h"

#define RESOLV_FILE "/etc/resolv.conf"
#define DNSPORT 53
#define DNSTIMEOUT 5                // dns 超时时间(s)
#define DNSTTL     8640             // dns 缓存时间(s)

class Dns_srv:public Con{
    int fd;
public:
    explicit Dns_srv(int fd);
    virtual void DnshandleEvent(uint32_t events);
    int query(const char *, int type);
    virtual ~Dns_srv();
};


class Dns_rcd{
public:
    int result;
    time_t gettime;
#define DNS_SUCCEED     0
#define DNS_ERR         1
#define DNS_NOTFUND     2
    std::vector<sockaddr_un> addrs;
    explicit Dns_rcd(int result = 0);
    explicit Dns_rcd(const std::vector<sockaddr_un>& addr);
    explicit Dns_rcd(const sockaddr_un &addr);
    void Down(const sockaddr_un &addr);
};


typedef void (*DNSCBfunc)(void *, const Dns_rcd& );

int dnsinit();
int query(const char *host, DNSCBfunc func, void *param);
void RcdDown(const char *hostname, const sockaddr_un &addr);
void dnstick();

#endif
