#ifndef HTTP_H__
#define HTTP_H__

#include "http_pack.h"

class HttpBase{
protected:
    char http_buff[HEADLENLIMIT];
    uint64_t http_expectlen;
    uint32_t http_getlen = 0;
#define HTTP_IGNORE_BODY_F          1
#define HTTP_STATUS_1XX             (1<<1)
#define HTTP_CHUNK_END_F            (1<<2)
#define HTTP_CLIENT_CLOSE_F        (1<<3)
#define HTTP_SERVER_CLOSE_F       (1<<4)
    uint32_t http_flag = 0;
    virtual void HeaderProc() = 0;
    void ChunkLProc();
    void ChunkBProc();
    void FixLenProc();
    void AlwaysProc();
    virtual ssize_t Read(void* buff, size_t len) = 0;
    //return false means don't continue handle the left data.
    virtual bool EndProc() = 0;
    virtual void ErrProc(int errcode) = 0;
    virtual ssize_t DataProc(const void *buff, size_t size) = 0;
public:
    void (HttpBase::*Http_Proc)() = &HttpBase::HeaderProc;
};


class HttpResponser:public HttpBase, virtual public ResObject{
    virtual void HeaderProc()override final;
protected:
    virtual void ReqProc(HttpReqHeader* req) = 0;
};

class HttpRequester:public HttpBase{
    virtual void HeaderProc()override final;
protected:
    virtual void ResProc(HttpResHeader* res) = 0;
};

#endif
