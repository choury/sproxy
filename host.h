#ifndef __HOST_H__
#define __HOST_H__

#include "peer.h"
#include "net.h"
#include "dns.h"




class Guest;

class Host:public Peer{
    char hostname[DOMAINLIMIT];
    uint16_t targetport;
    size_t testedaddr=0;
    std::vector<sockaddr_un> addr;
protected:
    virtual int showerrinfo(int ret,const char *s)override;
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    static void Dnscallback(Host * host,const Dns_rcd&&);
    virtual int connect();
public:
    Guest* guest;
    Host(int efd,Guest *guest,const char *hostname,uint16_t port);
    virtual void clean() override;
    static Host *gethost(Host *exist,const char *host,uint16_t port,int efd,Guest *guest);
};

#endif