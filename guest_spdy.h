#ifndef __SPDY_H__
#define __SPDY_H__

#include "guest_s.h"
#include "zlib.h"

class Guest_spdy:public Guest_s{
    z_stream destream;
    z_stream instream;
    int Write(const void* buf, size_t len,uint32_t id,uint8_t flag);
protected:
    virtual void defaultHE(uint32_t events);
    virtual void synHE(uint32_t events);
    virtual void synreplyHE(uint32_t events);
    virtual void goawayHE(uint32_t events);
    virtual void rstHE(uint32_t events);
    virtual void ctrlframedefultHE(uint32_t events);
public:
    Guest_spdy(Guest_s *);
    virtual ~Guest_spdy();
};

#endif