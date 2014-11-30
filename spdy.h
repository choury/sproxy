#ifndef __SPDY_H__
#define __SPDY_H__

#include "common.h"
#include "spdy_type.h"

class Spdy{
    char spdy_buff[HEADLENLIMIT];
    size_t spdy_expectlen=sizeof(spdy_head);
    enum{whead}state;
    ssize_t Spdy_read(void *buff,size_t buflen,size_t expectlen);
    void HeaderProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void SynProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void SynreplyProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void RstProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void GoawayProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void DataProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
    void DefaultProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t));
protected:
    size_t spdy_getlen=0;
    uint32_t stream_id;
    uchar spdy_flag;
    virtual void FrameProc(syn_frame *);
    virtual void FrameProc(syn_reply_frame *);
    virtual void FrameProc(rst_frame *);
    virtual void FrameProc(goaway_frame *);
    virtual void FrameProc(void *,size_t);
    void (Spdy::*Proc)(void *,size_t,void (Spdy::*)(uint32_t))=&Spdy::HeaderProc;
};


#endif