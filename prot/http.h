#ifndef HTTP_H__
#define HTTP_H__

#include "http_pack.h"
#include "base.h"

class HttpBase{
protected:
    uint64_t http_expectlen;
#define HTTP_IGNORE_BODY_F          1
#define HTTP_STATUS_1XX            (1<<1)
#define HTTP_CHUNK_END_F           (1<<2)
#define HTTP_CLIENT_CLOSE_F        (1<<3)
#define HTTP_SERVER_CLOSE_F        (1<<4)
    uint32_t http_flag = 0;
    virtual size_t HeaderProc(const char* buffer, size_t len) = 0;
    size_t ChunkLProc(const char* buffer, size_t len);
    size_t ChunkBProc(const char* buffer, size_t len);
    size_t FixLenProc(const char* buffer, size_t len);
    size_t AlwaysProc(const char* buffer, size_t len);
    //return false means don't continue handle the left data.
    virtual void EndProc() = 0;
    virtual void ErrProc() = 0;
    virtual ssize_t DataProc(const void *buff, size_t size) = 0;
public:
    size_t (HttpBase::*Http_Proc)(const char* buffer, size_t len) = &HttpBase::HeaderProc;
};


class HttpResponser:public HttpBase, virtual public RwObject{
    virtual size_t HeaderProc(const char* buffer, size_t len)override final;
protected:
    virtual void ReqProc(HttpReqHeader* req) = 0;
};

class HttpRequester:public HttpBase{
    virtual size_t HeaderProc(const char* buffer, size_t len)override final;
protected:
    virtual void ResProc(HttpResHeader* res) = 0;
};

#endif
