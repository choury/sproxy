#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "http.h"
#include "dns.h"

class Host:public Responser, public HttpReq{
    size_t testedaddr = 0;
    std::vector<sockaddr_un> addrs;
    bool udp_mode;
    int connect_tcp();
    int connect_udp();
protected:
    char hostname[DOMAINLIMIT];
    uint16_t port;
    HttpReqHeader req;

    
    int connect();
    virtual void destory();
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    
    virtual Ptr shared_from_this() override;
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    static void Dnscallback(Host * host, const Dns_rcd&&);
public:
    Host(){}
    Host(const char* hostname, uint16_t port, bool udp_mode = false);
    ~Host();
    
    virtual int showerrinfo(int ret, const char *s)override;
    virtual Ptr request(HttpReqHeader &req)override;
    virtual void ResProc(HttpResHeader &res)override;
    static Host* gethost(HttpReqHeader &req, Ptr responser_ptr);
    friend void hosttick();
};

#endif
