#ifndef PROXY2_H__
#define PROXY2_H__

#include "proxy.h"
#include "http2.h"

class Proxy2:public Proxy, public Http2Req{
    u_int32_t curid = 1;
    boost::bimap<Guest *, int> idmap;
    std::set<Peer *> waitlist;
protected:
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual ssize_t Write(const void* buff, size_t len)override;
    virtual ssize_t Write(Peer* who, const void *buff, size_t size)override;
    virtual Http2_header* SendFrame(const Http2_header *header, size_t addlen)override;
    virtual void DataProc(Http2_header *header)override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void ErrProc(int errcode)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
    virtual void defaultHE(u_int32_t events)override;
public:
    Proxy2( Proxy *const copy );
    size_t bufleft(Peer *)override;
    virtual void ResProc(HttpResHeader &res)override;
    virtual void Request(Guest* guest, HttpReqHeader& req, bool)override;
    virtual void clean(Peer *who, uint32_t errcode)override;
    virtual void wait(Peer *who)override;
};

extern Proxy2* proxy2; 

#endif