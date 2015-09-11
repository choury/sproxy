#ifndef GUEST_S2_H__
#define GUEST_S2_H__

#include "guest_s.h"
#include "http2.h"
#include <queue>

class Guest_s2: public Guest_s, public Http2Res{
    boost::bimap<Peer *, int> idmap;
    std::set<Peer *> waitlist;
    virtual void defaultHE(uint32_t events);
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual ssize_t Write(Peer* who, const void *buff, size_t size)override;
    virtual Http2_header* SendFrame(const Http2_header *header, size_t addlen)override;
    virtual void GoawayProc(Http2_header *header)override;
    virtual void Response(Peer *who, HttpResHeader& res)override;
    virtual void DataProc(Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void ErrProc(int errcode)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
    virtual void clean(Peer *who, uint32_t errcode)override;
public:
    Guest_s2(Guest_s *const copy);
    virtual int32_t bufleft(Peer*)override;
    virtual void wait(Peer *who)override;
    virtual int showstatus(Peer *who, char *buff)override;
};

#endif