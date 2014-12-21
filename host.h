#ifndef __HOST_H__
#define __HOST_H__

#include "peer.h"
#include "guest.h"
#include "parse.h"
#include "net.h"
#include "dns.h"


class Host:public Peer{
    char hostname[DOMAINLIMIT];
    uint16_t port;
    size_t testedaddr=0;
    std::vector<sockaddr_un> addrs;
protected:
    virtual int showerrinfo(int ret,const char *s)override;
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    static void Dnscallback(Host * host,const Dns_rcd&&);
    virtual int connect();
public:
    Host();
    Host(HttpReqHeader &req, Guest *guest,const char* hostname,uint16_t port);
    HttpReqHeader req;
    virtual ~Host();
    virtual void Request(HttpReqHeader &req,Guest *guest);
    static Host *gethost(HttpReqHeader &req,Guest* guest);
};

#endif