#ifndef __PROXY_SPDY_H__
#define __PROXY_SPDY_H__
 
#include "proxy.h"
#include "spdy.h"
#include "spdy_zlib.h"


class Proxy_spdy:public Proxy,public Spdy{
    uint32_t curid=1;
    std::map<Peer *,uint32_t> guest2id;
    std::map<uint32_t,Peer *> id2guest;
protected:
    virtual void ErrProc(int errcode)override;
    virtual ssize_t Read(void *buff,size_t size)override;
    virtual void defaultHE(uint32_t events)override;
    virtual void CFrameProc(syn_reply_frame*)override;
    virtual void CFrameProc(goaway_frame *)override;
    virtual ssize_t DFrameProc(uint32_t id,size_t size)override;
public:
    Proxy_spdy(Proxy* copy,Guest *guest);
    virtual void clean(Peer *)override;
    virtual void Request(HttpReqHeader* req, Guest* guest)override;
    static Host *getproxy_spdy(HttpReqHeader *,Guest* guest);
};

 
extern Proxy_spdy *proxy_spdy;
 
#endif