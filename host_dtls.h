#ifndef HOST_DTLS_H__
#define HOST_DTLS_H__

#include "host.h"
#include "openssl/ssl.h"

class Host_dtls:public Host{
    SSL *ssl = nullptr;
    SSL_CTX *ctx = nullptr;
protected:
    virtual int connect() override;
    virtual void shakehandHE(uint32_t events);
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
public:
    explicit Host_dtls(const char* hostname, uint16_t port);
    virtual int showerrinfo(int ret, const char *)override;
};

#endif
