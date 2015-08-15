#ifndef GUEST_S_H__
#define GUEST_S_H__

#include "guest.h"
#include "http2.h"

#include <openssl/ssl.h>

class Guest_s:public Guest ,public Http2Res {
    SSL *ssl;
    boost::bimap<Peer *, int> idmap;
    uint32_t accept_start_time;
protected:
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(Peer* who, const void *buff, size_t size)override;
    virtual ssize_t Write()override;
    virtual ssize_t Write2(const void *buff, size_t size)override;
    virtual void shakehandHE(uint32_t events);
    virtual void defaultHE_h2(uint32_t events);
    
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual void GoawayProc(Http2_header *header)override;
    virtual void DataProc2(Http2_header *header)override;
    virtual void RstProc(Http2_header* header)override;
public:
    Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL *ssl);
    virtual void shakedhand();
    virtual int showerrinfo(int ret, const char *s)override;
    virtual void Response(Peer *who, HttpResHeader& res)override;
    virtual void clean(Peer *who, uint32_t errcode)override;
    virtual ~Guest_s();
};

#endif
