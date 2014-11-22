#ifndef __SPDY_H__
#define __SPDY_H__

#include "guest_s.h"
#include "zlib.h"

class Hostinfo;

class Guest_spdy:public Guest_s{
    z_stream destream;
    z_stream instream;
    std::map<void *,Hostinfo> host2id;
    std::map<uint32_t,void *> id2host;
    virtual ssize_t Write(Peer* who,const void *buff,size_t size)override;
    virtual ssize_t Write(const void* buf, size_t len,uint32_t id,uint8_t flag);
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
    virtual void clean(Peer *)override;
    virtual ssize_t HeaderWrite(Hostinfo* hostinfo,const void *buff,size_t size);
    virtual ssize_t ChunkLWrite(Hostinfo* hostinfo,const void *buff,size_t size);
    virtual ssize_t ChunkBWrite(Hostinfo* hostinfo,const void *buff,size_t size);
    virtual ssize_t FixLenWrite(Hostinfo* hostinfo,const void *buff,size_t size);
};

class Hostinfo{
public:
    uint32_t id;
    char buff[HEALLENLIMIT];
    uint32_t readlen=0;
    uint32_t expectlen=0;
    ssize_t (Guest_spdy::*Write)(Hostinfo* who,const void *buff,size_t size)=&Guest_spdy::HeaderWrite;
    Hostinfo(){};
    Hostinfo(uint32_t id):id(id){};
};

#endif