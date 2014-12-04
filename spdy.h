#ifndef __SPDY_H__
#define __SPDY_H__

#include "common.h"
#include "spdy_type.h"
#include "spdy_zlib.h"
#include "parse.h"

class Spdy{
    char spdy_buff[HEADLENLIMIT];
    size_t spdy_expectlen;
    size_t spdy_getlen=0;
    uint32_t stream_id;
    void HeaderProc();
    void SynProc();
    void SynreplyProc();
    void RstProc();
    void GoawayProc();
    void DataProc();
    void DefaultProc();
protected:
    z_stream instream;
    z_stream destream;
    virtual ssize_t Read(void* buff,size_t len)=0;
    virtual void ErrProc(int errcode)=0;
    virtual void CFrameProc(syn_frame *);
    virtual void CFrameProc(syn_reply_frame *);
    virtual void CFrameProc(rst_frame *);
    virtual void CFrameProc(goaway_frame *);
    virtual ssize_t DFrameProc(uint32_t,size_t size);
    void (Spdy::*Proc)()=&Spdy::HeaderProc;

public:
    Spdy();
    ~Spdy();
};


#endif