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


class Dns_rcd{
public:
    time_t gettime;
    std::vector<sockaddr_un> addrs;
    explicit Dns_rcd();
    explicit Dns_rcd(std::vector<sockaddr_un>&& addrs);
    explicit Dns_rcd(const sockaddr_un &&addr);
    void Down(const sockaddr_un &addr);
};


typedef void (*DNSCBfunc)(void *, const char *hostname, const Dns_rcd&& );


void query(const char* host, DNSCBfunc func, void* param, uint16_t times=0);
void RcdDown(const char *hostname, const sockaddr_un &addr);
int dnsstatus(char* buff);
void flushdns();

#endif
