#ifndef PROXY2_H__
#define PROXY2_H__

#include "proxy.h"
#include "http2.h"

class Proxy2:public Proxy, public Http2Req{
    u_int32_t curid = 1;
    boost::bimap<Guest *, int> idmap;
protected:
    virtual ssize_t Read(void* buff, size_t len);
    virtual ssize_t Write(Peer* who, const void *buff, size_t size)override;
    virtual ssize_t Write2(const void* buff, size_t len)override;
    virtual void DataProc2(Http2_header *header)override;
    virtual void RstProc(Http2_header* header)override;
    virtual void ErrProc(int errcode)override;
    virtual void defaultHE(u_int32_t events)override;
public:
    Proxy2(int fd, SSL *ssl, SSL_CTX *ctx);
    size_t bufleft(Peer *)override;
    virtual void ResProc(HttpResHeader &res)override;
    virtual void Request(Guest* guest, HttpReqHeader& req, bool)override;
    virtual void clean(Peer *who, uint32_t errcode)override;
};

extern Proxy2* proxy2; 

#endif