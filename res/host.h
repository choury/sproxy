#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "prot/http.h"
#include "prot/dns.h"

class Requester;

class Host:public Responser, public HttpRequester {
    bool isconnected = false;
protected:
    Protocol protocol;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    HttpReqHeader* req = nullptr;
    
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ResProc(HttpResHeader* res)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc()override;

    virtual void* request(HttpReqHeader* req)override;
    virtual void connected();
public:
    explicit Host(Protocol protocol, const char* hostname, uint16_t port, bool use_ssl);
    virtual ~Host();
    
    virtual int32_t bufleft(void*) override;
    virtual ssize_t Send(void* buff, size_t size, void* index)override;

    virtual bool finish(uint32_t flags, void* index)override;
    virtual void writedcb(void * index) override;
    virtual void dump_stat()override;
    static Responser* gethost(const char* hostname, uint16_t port, Protocol protocol, HttpReqHeader* req, Responser* responser_ptr);
};

#endif
