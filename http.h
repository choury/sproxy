#ifndef HTTP_H__
#define HTTP_H__

#include "parse.h"
#include "object.h"

class HttpBase: public Object{
protected:
    char http_buff[HEADLENLIMIT];
    uint64_t http_expectlen;
    uint32_t http_getlen = 0;
    uint32_t http_flag = 0;
#define HTTP_IGNORE_BODY_F   1
#define HTTP_CHUNK_END_F     2
#define HTTP_CONNECT_F       3
    virtual void HeaderProc() = 0;
    void ChunkLProc();
    void ChunkBProc();
    void FixLenProc();
    void AlwaysProc();
    virtual ssize_t Read(void* buff, size_t len) = 0;
    virtual void ErrProc(int errcode) = 0;
    virtual ssize_t DataProc(const void *buff, size_t size) = 0;
public:
    void (HttpBase::*Http_Proc)() = &HttpBase::HeaderProc;
};


class HttpRes:public HttpBase{
    virtual void HeaderProc()override final;
protected:
    virtual void ReqProc(HttpReqHeader &req) = 0;
};

class HttpReq:public HttpBase{
    virtual void HeaderProc()override final;
protected:
    virtual void ResProc(HttpResHeader &res) = 0;
};

#endif
