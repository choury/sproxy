#ifndef SSL_IO_H_
#define SSL_IO_H_

#include "netio.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

class SslRWer: public StreamRWer {
protected:
    SSL *ssl;
    SSL_CTX* ctx = nullptr;

public:
    virtual ssize_t Read(void* buff, size_t len) override;
    virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
    explicit SslRWer(int fd, const sockaddr_storage* peer,
                     SSL_CTX* ctx,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    explicit SslRWer(const char* hostname, uint16_t port, Protocol protocol,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~SslRWer() override;

    virtual int saccept();
    virtual int sconnect();
    virtual void waitconnectHE(RW_EVENT events) override;
    virtual void shakehandHE(RW_EVENT events);
    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    void set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg);
    virtual void dump_status(Dumper dp, void* param) override;
};

#endif
