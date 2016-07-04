#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "http.h"
#include "dns.h"

class Host:public Responser, public HttpReq{
    size_t testedaddr = 0;
    std::vector<sockaddr_un> addrs;
protected:
    char hostname[DOMAINLIMIT];
    uint16_t port;
    HttpReqHeader req;

    
    int connect();
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    
    virtual Ptr shared_from_this() override;
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    static void Dnscallback(Host * host, const Dns_rcd&&);
public:
    Ptr guest_ptr;
    explicit Host(Host&& copy);
    explicit Host(const char* hostname, uint16_t port);
    ~Host();
    
    virtual int showerrinfo(int ret, const char *s)override;
    virtual Ptr request(HttpReqHeader &req)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual void ResProc(HttpResHeader &res)override;
    static Ptr gethost(HttpReqHeader &req, Ptr responser_ptr);
    friend void hosttick();
};

#endif
