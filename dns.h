#ifndef __DNS_H__
#define __DNS_H__


#include <netdb.h>
#include <vector>
#include "con.h"


class Dns_srv:public Con{
public:
    int fd;
    virtual void handleEvent(uint32_t events) override;
    int query(const char *,int type);
};


union sockaddr_un{
    sockaddr addr;
    sockaddr_in addr_in;
    sockaddr_in6 addr_in6;
};

class Dns_rcd{
public:
    int result;
#define DNS_ERR         1
#define DNS_NOTFUND     2
    std::vector<sockaddr_un> addr;
    Dns_rcd(int result=0):result(result){};
    Dns_rcd(const std::vector<sockaddr_un>& addr):result(0),addr(addr){};
    Dns_rcd(const sockaddr_un &addr):result(0){this->addr.push_back(addr);};
};


typedef void (*DNSCBfunc)(void *,const Dns_rcd& );

int dnsinit(int efd);
void query(const char *host ,DNSCBfunc func,void *param);


#endif