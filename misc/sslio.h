#ifndef SSL_IO_H_
#define SSL_IO_H_

#include "simpleio.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

class SslRWer: public StreamRWer {
protected:
    SSL *ssl;
    SSL_CTX* ctx = nullptr;
    int get_error(int ret);

    virtual ssize_t Read(void* buff, size_t len) override;
    virtual ssize_t Write(const void* buff, size_t len) override;
public:
    explicit SslRWer(int fd, SSL_CTX* ctx, std::function<void(int ret, int code)> errorCB);
    explicit SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB);
    virtual ~SslRWer();

    virtual int saccept();
    virtual int sconnect();
    virtual void waitconnectHE(uint32_t events) override;
    virtual void shakehandHE(uint32_t events);
    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    void set_hostname_callback(void (* cb)(void));
};

#endif
