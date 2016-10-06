#ifndef PROXY2_H__
#define PROXY2_H__

#include "responser.h"
#include "http2.h"
#include "binmap.h"
#include "ssl_abstract.h"

class Proxy2:public Responser, public Http2Req{
    uint32_t curid = 1;
    uint32_t lastping = 0;
    uint32_t lastrecv  = 0;
    binmap<Requester *, int> idmap;
    std::set<Peer *> waitlist;
    SSL_CTX *ctx;
    Ssl *ssl;
protected:
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual ssize_t Write(const void* buff, size_t len)override;
    virtual void SendFrame(Http2_header *header)override;
    virtual void DataProc(const Http2_header *header)override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void PingProc(Http2_header *header)override;
    virtual void ErrProc(int errcode)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
    virtual void defaultHE(uint32_t events);
public:
    explicit Proxy2(int fd, SSL_CTX *ctx, Ssl *ssl);
    virtual ~Proxy2();
    
    virtual void clean(uint32_t errcode, Peer *who, uint32_t id = 0)override;
    virtual ssize_t Write(void *buff, size_t size, Peer *who, uint32_t id=0)override;
    
    virtual void ResProc(HttpResHeader &res)override;
    virtual void request(HttpReqHeader& req)override;
    
    virtual int32_t bufleft(Peer *)override;
    virtual void wait(Peer *who)override;
    virtual void writedcb(Peer *who)override;
//    virtual int showerrinfo(int ret, const char* s)override;
    void check_alive();
};

extern Proxy2* proxy2; 
void flushproxy2();

#endif
