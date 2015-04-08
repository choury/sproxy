#ifndef PROXY_H__
#define PROXY_H__

#include <openssl/ssl.h>

#include "host.h"
#include "dns.h"


class Proxy : public Host{
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
protected:
    ssize_t Read(void *buff, size_t size)override;
    ssize_t Write()override;
    int showerrinfo(int ret, const char *)override;
    void waitconnectHE(uint32_t events)override;
    virtual void shakehandHE(uint32_t events);
public:
    Proxy(HttpReqHeader &req, Guest *guest);
    virtual ~Proxy();
    static Host *getproxy(HttpReqHeader &req, Guest *guest);
};

#endif
