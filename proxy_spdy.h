#ifndef __PROXY_SPDY_H__
#define __PROXY_SPDY_H__
 
#include "proxy.h"
#include "spdy_zlib.h"


class Proxy_spdy:public Proxy{
    uint32_t curid=1;
    z_stream instream;
    z_stream destream;
    std::map<void *,uint32_t> guest2id;
    std::map<uint32_t,void *> id2guest;
    bool openframe(Guest* guest, HttpReqHeader* http);
protected:
    virtual void defaultHE(uint32_t events)override;
public:
    Proxy_spdy(Proxy* copy);
    virtual void clean(Peer *)override;
    static Host *getproxy_spdy(Guest* guest,HttpReqHeader *);
};

 
extern Proxy_spdy *proxy_spdy;
 
#endif