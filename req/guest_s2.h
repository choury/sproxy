#ifndef GUEST_S2_H__
#define GUEST_S2_H__

#include "requester.h"
#include "prot/http2.h"
#include "misc/vssl.h"

struct ResStatus{
    Responser *res_ptr;
    void*      res_index;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
};

class Guest_s2: public Requester, public Http2Responser {
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
#ifndef NDEBUG
    virtual void PingProc(Http2_header *header)override;
#endif
public:
    explicit Guest_s2(int fd, const char *ip, uint16_t port, Ssl *ssl);
    explicit Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl *ssl);
    virtual ~Guest_s2();
    
    virtual void ResetResponser(Responser *r, void* index)override;
    virtual void clean(uint32_t errcode, void* index)override;

    virtual ssize_t Write(void *buff, size_t size, void* index)override;
    
    virtual int32_t bufleft(void* index)override;
    virtual void wait(void* index)override;
    virtual void response(HttpResHeader&& res)override;
    virtual void writedcb(void* index)override;
    static void peer_lost(Guest_s2* g);
};

#endif
