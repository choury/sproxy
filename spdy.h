#ifndef __SPDY_H__
#define __SPDY_H__

#include "guest_s.h"
#include "zlib.h"

class Spdy:public Guest_s{
    z_stream zstream;
    virtual void defaultHE(uint32_t events);
    virtual void synHE(uint32_t events);
    virtual void synreplyHE(uint32_t events);
    virtual void rstHE(uint32_t events);
    virtual void ctrlframedefultHE(uint32_t events);
public:
    Spdy(Guest_s *);
};

#endif