#ifndef SSL_ABSTRACT_H_
#define SSL_ABSTRACT_H_

#include "base.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

class SRWer: public RWer{
protected:
    SSL *ssl;
    SSL_CTX* ctx;
    int get_error(int ret);

    virtual ssize_t Read(void* buff, size_t len) override;
    virtual ssize_t Write(const void* buff, size_t len) override;
public:
    explicit SRWer(int fd, SSL_CTX* ctx, std::function<void(int ret, int code)> errorCB);
    explicit SRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB);
    virtual ~SRWer();

    virtual int saccept();
    virtual int sconnect();
    virtual void waitconnectHE(int events) override;
    virtual void shakehandHE(int events);
    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    void set_hostname_callback(void (* cb)(void));
};

#endif
