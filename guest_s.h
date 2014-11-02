#ifndef __GUEST_S_H__
#define __GUEST_S_H__

#include <openssl/ssl.h>

#include "guest.h"
#include "net.h"



class Guest_s:public Guest {
    SSL *ssl;
    enum{http1_1,spdy2,spdy3_1} protocol=http1_1;
    virtual int Write()override;
    virtual void shakehandHE(uint32_t events);
    virtual void spdyHE(uint32_t events);
    virtual void spdysynHE(uint32_t events);
    virtual int Read(void *buff,size_t size)override;
public:
    Guest_s(int fd,int efd,SSL *ssl);
    virtual void shakedhand();
    virtual int showerrinfo(int ret,const char *s)override;
    virtual ~Guest_s();
};



#endif