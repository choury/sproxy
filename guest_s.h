#ifndef GUEST_S_H__
#define GUEST_S_H__

#include "guest.h"

#include <openssl/ssl.h>

class Guest_s:public Guest {
    SSL *ssl;
    uint32_t accept_start_time;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void shakehandHE(uint32_t events);
    virtual void shakedhand();
    virtual void ReqProc(HttpReqHeader &req)override;
public:
    Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL *ssl);
    Guest_s(struct sockaddr_in6 *myaddr, SSL *ssl); 
    Guest_s( Guest_s *const copy );
    virtual int showerrinfo(int ret, const char *s)override;
    virtual ~Guest_s();
};

#endif
