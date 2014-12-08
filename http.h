#ifndef __HTTP_H__
#define __HTTP_H__

#include "common.h"
#include "parse.h"

#define HEAD_TOO_LAGER 1
#define HTTP_ERROR     2

class Http{
    char http_buff[HEADLENLIMIT];
    size_t http_getlen=0;
    size_t http_expectlen;
    void HeaderProc();
    void ChunkLProc();
    void ChunkBProc();
    void FixLenProc();
    void AlwaysProc();
protected:
    virtual ssize_t Read(void* buff,size_t len)=0;
    virtual void ErrProc(int errcode)=0;
    virtual void ReqProc(HttpReqHeader &req);
    virtual void ResProc(HttpResHeader &res);
    virtual ssize_t DataProc(const void *buff,size_t size)=0;
public:
    void (Http::*Http_Proc)()=&Http::HeaderProc;
};



#endif