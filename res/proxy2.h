#ifndef PROXY2_H__
#define PROXY2_H__

#include "responser.h"
#include "prot/http2.h"
#include "misc/vssl.h"
#include "misc/rudp.h"

struct ReqStatus{
    Requester *req_ptr;
    void*      req_index;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加

#define STREAM_HEAD_ENDED    1
#define STREAM_WRITE_CLOSED (1<<1)
#define STREAM_READ_CLOSED  (1<<2)
    uint32_t   req_flags;
};

class Proxy2:public Responser, public Http2Requster {
    std::map<uint32_t, ReqStatus> statusmap;
    Rudp_c*  rudp = nullptr;
    SSL_CTX* ctx = nullptr;
    Ssl*     ssl = nullptr;
    uint16_t port = 0;
#ifdef __ANDROID__
    uint32_t receive_time;
    uint32_t ping_time;
#endif
    void init_helper();
protected:
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual ssize_t Write(const void* buff, size_t len)override;

    virtual void PushFrame(Http2_header *header)override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void PingProc(Http2_header *header)override;
    virtual void ErrProc(int errcode)override;
    virtual void ResProc(HttpResHeader* res)override;
    virtual void DataProc(uint32_t id, const void *data, size_t len)override;
    virtual void EndProc(uint32_t id) override;
    virtual void GoawayProc(Http2_header * header) override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;

    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events) override;
    virtual void deleteLater(uint32_t errcode) override;

    static void Dnscallback(Proxy2* host, const char *hostname, std::list<sockaddr_un> addrs);
public:
    using Responser::request;
    explicit Proxy2(const char* host, uint16_t port); //for rudp
    explicit Proxy2(int fd, SSL_CTX *ctx, Ssl *ssl);
    virtual ~Proxy2();


    virtual int32_t bufleft(void* index)override;
    virtual ssize_t Send(void *buff, size_t size, void* index)override;
    virtual void writedcb(void* index)override;
    
    virtual void* request(HttpReqHeader* req)override;
    
    virtual bool finish(uint32_t flags, void* index)override;

    virtual void dump_stat()override;
    static int ping_check(Proxy2 *p);
    static int connection_lost(Proxy2 *p);
};

extern Proxy2* proxy2; 

#endif
