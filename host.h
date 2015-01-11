#ifndef __HOST_H__
#define __HOST_H__

#include "peer.h"
#include "guest.h"
#include "dns.h"


class Host:public Peer{
    size_t testedaddr=0;
    std::vector<sockaddr_un> addrs;
protected:
    char hostname[DOMAINLIMIT];
    uint16_t port;
    virtual int showerrinfo(int ret,const char *s)override;
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    static void Dnscallback(Host * host,const Dns_rcd&&);
    virtual int connect();
    virtual ssize_t DataProc(const void *buff,size_t size)override;
public:
    Host();
    Host(HttpReqHeader &req, Guest *guest,Http::Initstate state=ALWAYS);
    Host(HttpReqHeader &req, Guest *guest,const char* hostname,uint16_t port);
    HttpReqHeader req;
    virtual ~Host();
    virtual void Request(HttpReqHeader &req,Guest *guest);
    static Host *gethost(HttpReqHeader &req,Guest* guest);
};

#endif