#ifndef GUEST_S_H__
#define GUEST_S_H__

#include "guest.h"
#include "vssl.h"

class Guest_s:public Guest {
    Ssl *ssl;
    uint32_t accept_start_time;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void shakehandHE(uint32_t events);
    virtual void discard()override;
public:
    using Guest::Write; //make clang happy
    explicit Guest_s(int fd, struct sockaddr_in6 *myaddr, Ssl *ssl);

    virtual ~Guest_s();
};

#endif
