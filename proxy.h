#ifndef PROXY_H__
#define PROXY_H__

#include "host.h"
#include "vssl.h"

class Proxy : public Host{
    SSL_CTX *ctx = nullptr;
    Ssl *ssl = nullptr;
protected:
    HttpReqHeader req;
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void waitconnectHE(uint32_t events)override;
    virtual void shakehandHE(uint32_t events);
public:
    explicit Proxy(const char *hostname, uint16_t port, Protocol protocol);
    virtual ~Proxy();
    
    virtual void discard()override;
    virtual void request(HttpReqHeader &req)override;
    static Responser* getproxy(HttpReqHeader &req, Responser* responser_ptr);
};

#endif
