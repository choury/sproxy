#ifndef __GUEST_SPDY_H__
#define __GUEST_SPDY_H__

#include "guest_s.h"
#include "spdy.h"
#include "host.h"

class Host_spdy:public Host{
    virtual void waitconnectHE(uint32_t events)override;
    virtual void ResProc(HttpResHeader& res)override;
    virtual ssize_t DataProc(const void *buff,size_t size)override;
public:
    uint32_t id;
    Host_spdy(uint32_t id, HttpReqHeader& req, Guest* guest);
};

class Guest_spdy:public Guest_s,public Spdy{
    std::map<uint32_t,Host_spdy *> id2host;
    virtual ssize_t Read(void *buff,size_t size)override;
    virtual void Reset(uint32_t id,uint32_t errcode);
    virtual void ErrProc(int errcode,uint32_t id)override;
    virtual void defaultHE(uint32_t events)override;
    
    virtual void CFrameProc(syn_frame *)override;
    virtual void CFrameProc(ping_frame *)override;
    virtual void CFrameProc(rst_frame *)override;
    virtual void CFrameProc(goaway_frame *)override;
    virtual ssize_t DFrameProc(void *buff,size_t size,uint32_t id)override;
public:
    Guest_spdy(Guest_s *);
    virtual ~Guest_spdy();
    virtual size_t bufleft()override;
    virtual void clean(Peer *who)override;
    virtual void Response(HttpResHeader &res,uint32_t id);
};



#endif