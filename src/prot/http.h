#ifndef HTTP_H__
#define HTTP_H__

#include "common/base.h"
#include "http_pack.h"

class HttpBase{
protected:
    uint64_t http_expectlen = 0;
#define HTTP_IGNORE_BODY_F          1u
#define HTTP_STATUS_1XX            (1u<<1u)
#define HTTP_CHUNK_END_F           (1u<<2u)
//#define HTTP_READ_CLOSE_F          (1u<<3u)
//#define HTTP_WRITE_CLOSE_F         (1u<<4u)
    uint32_t http_flag = 0;
    virtual size_t HeaderProc(const char* buffer, size_t len) = 0;
    size_t ChunkLProc(const char* buffer, size_t len);
    size_t ChunkBProc(const char* buffer, size_t len);
    size_t FixLenProc(const char* buffer, size_t len);
    size_t AlwaysProc(const char* buffer, size_t len);
    virtual void EndProc() = 0;
    virtual void ErrProc() = 0;
    virtual ssize_t DataProc(const void *buff, size_t size) = 0;
public:
    size_t (HttpBase::*Http_Proc)(const char* buffer, size_t len) = &HttpBase::HeaderProc;
};


class HttpResponser:public HttpBase{
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
