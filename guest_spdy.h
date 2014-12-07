#ifndef __GUEST_SPDY_H__
#define __GUEST_SPDY_H__

#include "guest_s.h"
#include "spdy.h"
#include "host.h"

class Hostinfo;

class Guest_spdy:public Guest_s,public Spdy{
    std::map<Peer *,Hostinfo*> host2id;
    std::map<uint32_t,Host *> id2host;
    virtual ssize_t Read(void *buff,size_t size)override;
    virtual void ErrProc(int errcode,uint32_t id)override;
    virtual void defaultHE(uint32_t events);
public:
    Guest_spdy(Guest_s *);
    virtual ~Guest_spdy();
    virtual void Response(HttpResHeader &res,uint32_t id);
    virtual void connected(void *who)override;
    virtual ssize_t Write(Peer* who,const void *buff,size_t size)override;
    virtual void clean(Peer *)override;
    void clean(Hostinfo *hostinfo);
    virtual void CFrameProc(syn_frame *)override;
    virtual void CFrameProc(rst_frame *)override;
    virtual void CFrameProc(goaway_frame *)override;
    virtual ssize_t DFrameProc(uint32_t,size_t size)override;
};

class Hostinfo:public Http{
    char wbuff[1024*1024];
    size_t writelen=0;
    ssize_t Read(void *buff,size_t size)override;
    virtual void ResProc(HttpResHeader &res);
    virtual ssize_t DataProc(const void *buff,size_t size)override;
    virtual void ErrProc(int errcode)override;
public:
    uint32_t id;
    Guest_spdy *guest;
    Host *host;
    Hostinfo();
    Hostinfo(uint32_t id,Guest_spdy *guest,Host *host);
    virtual ~Hostinfo();
    ssize_t Write(const void *buff,size_t size);
};

#endif