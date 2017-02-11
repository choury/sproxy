#ifndef DNS_H__
#define DNS_H__

#include "con.h"
#include "net.h"

#include <vector>

#include <unistd.h>
#include <time.h>
#include <netinet/in.h>

class Dns_srv:public Con{
public:
    explicit Dns_srv(int fd);
    virtual void DnshandleEvent(uint32_t events);
    int query(const char *host, int type, uint32_t id);
};


typedef void (*DNSCBfunc)(void *, const char *hostname, std::vector<sockaddr_un> addrs);


void query(const char* host, DNSCBfunc func, void* param, uint16_t times=0);
void RcdDown(const char *hostname, const sockaddr_un &addr);

#endif
