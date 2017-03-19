#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "prot/http.h"
#include "misc/dns.h"

class Requester;

class Host:public Responser, public HttpRequester {
protected:
    size_t testedaddr = 0;
    std::vector<sockaddr_un> addrs;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    Protocol protocol;
    Requester* requester_ptr = nullptr;
    void*      requester_index = nullptr;

    
    virtual int connect();
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    static void Dnscallback(Host* host, const char *hostname, std::vector<sockaddr_un> addrs);
    virtual void* request(HttpReqHeader&& req)override;
public:
    explicit Host(const char* hostname, uint16_t port, Protocol protocol);
    ~Host();
    
    virtual void clean(uint32_t errcode, void* index)override;
    virtual void ResProc(HttpResHeader&& res)override;
    static Host* gethost(HttpReqHeader& req, Responser* responser_ptr);
    static void con_timeout(Host* host);
    static void vpn_aged(Host* host);
};

#endif
