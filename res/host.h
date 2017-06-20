#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "prot/http.h"
#include "prot/dns.h"

class Requester;

struct HostStatus{
    Requester* req_ptr;
    void*      req_index;
    char       hostname[DOMAINLIMIT];
    uint16_t   port;
    Protocol   protocol;
};

class Host:public Responser, public HttpRequester {
protected:
    int testedaddr = -1;
    std::vector<sockaddr_un> addrs;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    Protocol protocol;
    HostStatus status;
    std::list<HttpReq> reqs;
    
    virtual int connect();
    virtual void waitconnectHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ResProc(HttpResHeader* res)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void ErrProc(int errcode)override;

    virtual void* request(HttpReqHeader* req)override;
    virtual void discard()override;
    ssize_t Write_buff();

    static void Dnscallback(Host* host, const char *hostname, std::list<sockaddr_un> addrs);
public:
    explicit Host(const char* hostname, uint16_t port, Protocol protocol);
    ~Host();
    
    virtual int32_t bufleft(void*) override;
    virtual ssize_t Send(void* buff, size_t size, void* index)override;

    virtual void clean(uint32_t errcode, void* index)override;
    virtual void dump_stat()override;
    static Host* gethost(HttpReqHeader* req, Responser* responser_ptr);
    static void con_timeout(Host* host);
};

#endif
