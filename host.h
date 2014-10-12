#ifndef __HOST_H__
#define __HOST_H__

#include "peer.h"
#include "net.h"
#include "dns.h"

class Guest;

class Host:public Peer{
    char hostname[DOMAINLIMIT];
    uint16_t targetport;
    std::vector<sockaddr_un> addr;
protected:
public:
    Guest* guest;
    Host(int efd,Guest *guest,const char *hostname,uint16_t port);
    virtual void handleEvent(uint32_t events)override;
    virtual void clean() override;
    static Host *gethost(Host *exist,const char *host,uint16_t port,int efd,Guest *guest);
    static void connect(Host * host,const Dns_rcd&&);
};

#endif