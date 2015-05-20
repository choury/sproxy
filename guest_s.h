#ifndef GUEST_S_H__
#define GUEST_S_H__

#include <openssl/ssl.h>

#include "guest.h"


class Guest_s:public Guest {
    SSL *ssl;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write()override;
    virtual void shakehandHE(uint32_t events);
    virtual void ReqProc(HttpReqHeader &req)override;
public:
    Guest_s(int fd, SSL *ssl);
    explicit Guest_s(Guest_s* copy);
    virtual void shakedhand();
    virtual int showerrinfo(int ret, const char *s)override;
    virtual ~Guest_s();
};

#endif
