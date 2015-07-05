#ifndef PROXY_H__
#define PROXY_H__

#include "host.h"

#include <openssl/ssl.h>

class Proxy : public Host{
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write()override;
    virtual int showerrinfo(int ret, const char *)override;
    virtual void waitconnectHE(uint32_t events)override;
    virtual void shakehandHE(uint32_t events);
public:
    Proxy(int fd, SSL* ssl, SSL_CTX* ctx):Host(fd), ssl(ssl), ctx(ctx){}
    Proxy(HttpReqHeader &req, Guest *guest);
    virtual ~Proxy();
    static Host *getproxy(HttpReqHeader &req, Guest *guest);
    virtual int showstatus(char *buff)override;
};

#endif
