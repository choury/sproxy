#ifndef __PROXY_H__
#define __PROXY_H__

#include <openssl/ssl.h>

#include "host.h"





class Proxy : public Host{
    SSL *ssl=nullptr;
    SSL_CTX *ctx=nullptr;
    virtual int Write()override;
public:
    Proxy(int efd,Guest *guest);
    virtual ~Proxy();
    virtual void handleEvent(uint32_t events)override;
    virtual int Read(char *buff,size_t size)override;
    virtual void connected();
    static Host *getproxy(Host *exist,int efd,Guest *guest);
};




#endif