#ifndef PROXY2_H__
#define PROXY2_H__

#include "responser.h"
#include "http2.h"
#include "vssl.h"

struct ReqStatus{
    Requester *req_ptr;
    uint32_t   req_id;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
};

class Proxy2:public Responser, public Http2Requster {
    uint32_t curid = 1;
    uint32_t lastping = 0;
    uint32_t lastrecv  = 0;
    std::map<uint32_t, ReqStatus> statusmap;
    std::set<uint32_t> waitlist;
    SSL_CTX *ctx;
    Ssl *ssl;
protected:
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual ssize_t Write(const void* buff, size_t len)override;
    virtual void PushFrame(Http2_header *header)override;
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
    
    virtual void clean(uint32_t errcode, uint32_t id)override;
    virtual ssize_t Write(void *buff, size_t size, uint32_t)override;
    
    virtual void ResProc(HttpResHeader&& res)override;
    virtual uint32_t request(HttpReqHeader&& req)override;
    
    virtual int32_t bufleft(uint32_t id)override;
    virtual void wait(uint32_t id)override;
    virtual void writedcb(uint32_t id)override;
    void check_alive();
};

extern Proxy2* proxy2; 
void flushproxy2();

#endif
