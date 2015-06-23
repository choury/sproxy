#ifndef GUEST_S_H__
#define GUEST_S_H__

#include "guest.h"
#include "http2.h"

#include <openssl/ssl.h>

class Guest_s:public Guest ,public Http2 {
    SSL *ssl;
    boost::bimap<Peer *, int> idmap;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual ssize_t Write(Peer* who, const void *buff, size_t size)override;
    virtual ssize_t Write()override;
    virtual void shakehandHE(uint32_t events);
    virtual void defaultHE_h2(uint32_t events);
    
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual void RstProc(Http2_header *header)override;
    virtual void GoawayProc(Http2_header *header)override;
    virtual ssize_t DataProc(Http2_header *header)override;
public:
    Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL *ssl);
    virtual void shakedhand();
    virtual int showerrinfo(int ret, const char *s)override;
    virtual void Response(Peer *who, HttpResHeader& res)override;
    virtual void clean(Peer *who)override;
    virtual ~Guest_s();
};

#endif
