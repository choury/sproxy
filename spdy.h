#ifndef __SPDY_H__
#define __SPDY_H__

#include "common.h"
#include "spdy_type.h"
#include "spdy_zlib.h"
#include "parse.h"

class Spdy{
    char spdy_buff[HEADLENLIMIT];
    uchar  spdy_flag;
    size_t spdy_expectlen;
    size_t spdy_getlen=0;
    uint32_t stream_id;
    void HeaderProc();
    void SynProc();
    void SynreplyProc();
    void PingProc();
    void RstProc();
    void GoawayProc();
    void DataProc();
    void DropProc();
protected:
    z_stream instream;
    z_stream destream;
    virtual ssize_t Read(void* buff,size_t len)=0;
    virtual void ErrProc(int errcode,uint32_t id)=0;
    virtual void CFrameProc(syn_frame *);
    virtual void CFrameProc(syn_reply_frame *);
    virtual void CFrameProc(ping_frame *);
    virtual void CFrameProc(rst_frame *);
    virtual void CFrameProc(goaway_frame *);
    virtual ssize_t DFrameProc(void *buff,size_t size,uint32_t id);
    void (Spdy::*Spdy_Proc)()=&Spdy::HeaderProc;

public:
    Spdy();
    ~Spdy();
};


#endif