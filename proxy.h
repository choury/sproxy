#ifndef __PROXY_H__
#define __PROXY_H__

#include <openssl/ssl.h>

#include "host.h"

#include "dns.h"

class Proxy : public Host{
    SSL *ssl=nullptr;
    SSL_CTX *ctx=nullptr;
    virtual int Write()override;
    virtual void shakedhand();
    virtual int showerrinfo(int ret,const char *)override;
    virtual void waitconnectHE(uint32_t events)override;
    virtual void shakehandHE(uint32_t events);
    virtual int Read(void *buff,size_t size)override;
public:
    Proxy(int efd,Guest *guest);
    virtual ~Proxy();
    static Host *getproxy(Host *exist,int efd,Guest *guest);
};




#endif