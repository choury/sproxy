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
    ssize_t Spdy_read(void *buff,size_t buflen,size_t expectlen);
    void HeaderProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void SynProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void SynreplyProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void RstProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void GoawayProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void DataProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void DefaultProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
protected:
    uint32_t curid=1;
    z_stream instream;
    z_stream destream;
    virtual void CFrameProc(syn_frame *);
    virtual void CFrameProc(syn_reply_frame *);
    virtual void CFrameProc(rst_frame *);
    virtual void CFrameProc(goaway_frame *);
    virtual void DFrameProc(void* buff, size_t buflen, uint32_t id);
    void (Spdy::*Proc)(void *,size_t,void (Spdy::*)(uint32_t))=&Spdy::HeaderProc;

public:
    Spdy();
    ~Spdy();
};


#endif