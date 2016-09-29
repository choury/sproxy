#ifndef GUEST_S_H__
#define GUEST_S_H__

#include "guest.h"

#include <openssl/ssl.h>

class Guest_s:public Guest {
    SSL *ssl;
    uint32_t accept_start_time;
    Protocol protocol;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void shakehandHE(uint32_t events);
public:
    using Guest::Write; //make clang happy
    explicit Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL *ssl, Protocol protocol);
    
    virtual void discard()override;
    virtual int showerrinfo(int ret, const char *s)override;
    virtual ~Guest_s();
};

#endif
