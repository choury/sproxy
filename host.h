#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "http.h"
#include "dns.h"

class Requester;

class Host:public Responser, public HttpReq{
protected:
    size_t testedaddr = 0;
    std::vector<sockaddr_un> addrs;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    Protocol protocol;

    
    virtual int connect();
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    static void Dnscallback(Host * host, const char *hostname, const Dns_rcd&&);
public:
    Requester* requester_ptr = nullptr;
    explicit Host(const char* hostname, uint16_t port, Protocol protocol);
    ~Host();
    
    virtual void ResetRequester(Requester *r)override;
    virtual void discard()override;
    virtual void request(HttpReqHeader &req)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual void ResProc(HttpResHeader &res)override;
    static Host* gethost(HttpReqHeader &req, Responser* responser_ptr);
    friend void hosttick(void *);
};

#endif
