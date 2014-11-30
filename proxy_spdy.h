#ifndef __PROXY_SPDY_H__
#define __PROXY_SPDY_H__
 
#include "proxy.h"
#include "spdy.h"
#include "spdy_zlib.h"


class Proxy_spdy:public Proxy,public Spdy{
    uint32_t curid=1;
    z_stream instream;
    z_stream destream;
    std::map<Peer *,uint32_t> guest2id;
    std::map<uint32_t,Peer *> id2guest;
protected:
    void ErrProc(uint32_t errcode);
    virtual void defaultHE(uint32_t events)override;
    virtual void FrameProc(syn_reply_frame*);
    virtual void FrameProc(goaway_frame *);;
    virtual void FrameProc(void *,size_t);
public:
    Proxy_spdy(Proxy* copy,Guest *guest);
    virtual void clean(Peer *)override;
    virtual void Request(HttpReqHeader* req, Guest* guest)override;
    static Host *getproxy_spdy(HttpReqHeader *,Guest* guest);
};

 
extern Proxy_spdy *proxy_spdy;
 
#endif