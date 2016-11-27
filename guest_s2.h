#ifndef GUEST_S2_H__
#define GUEST_S2_H__

#include "requester.h"
#include "http2.h"
#include "vssl.h"

struct ResStatus{
    Responser *res_ptr;
    uint32_t   res_id;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
};

class Guest_s2: public Requester, public Http2Responser {
    uint32_t last_interactive ;
    std::map<uint32_t, ResStatus> statusmap;
    std::set<uint32_t> waitlist;
    Ssl *ssl;
protected:
    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void PushFrame(Http2_header *header)override;
    virtual void GoawayProc(Http2_header *header)override;
    virtual void DataProc(const Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader&& req)override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void ErrProc(int errcode)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
public:
    explicit Guest_s2(int fd, const char *ip, uint16_t port, Ssl *ssl);
    explicit Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl *ssl);
    virtual ~Guest_s2();
    
    virtual void ResetResponser(Responser *r, uint32_t id)override;
    virtual void clean(uint32_t errcode, uint32_t id)override;

    virtual ssize_t Write(void *buff, size_t size, uint32_t)override;
    
    virtual int32_t bufleft(uint32_t id)override;
    virtual void wait(uint32_t id)override;
    virtual void response(HttpResHeader&& res)override;
    virtual void writedcb(uint32_t id)override;
    void check_alive();
};

#endif
