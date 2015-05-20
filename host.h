#ifndef HOST_H__
#define HOST_H__

#include "peer.h"
#include "guest.h"
#include "dns.h"


class Host:public Peer, public Http{
    size_t testedaddr = 0;
    std::vector<sockaddr_un> addrs;
protected:
    char hostname[DOMAINLIMIT];
    uint16_t port;
    HttpReqHeader req;
    
    int showerrinfo(int ret, const char *s)override;
    virtual int connect();
    virtual void destory(const char *tip);
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    
    static void Dnscallback(Host * host, const Dns_rcd&&);
public:
    Host(HttpReqHeader &req, Guest *guest, Http::Initstate state = ALWAYS);
    Host(HttpReqHeader &req, Guest *guest, const char* hostname, uint16_t port);
    virtual void Request(HttpReqHeader &req, Guest *guest);
    static Host *gethost(HttpReqHeader &req, Guest* guest);
    friend void ConnectSet::tick();
};

#endif
