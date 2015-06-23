#ifndef HTTP_H__
#define HTTP_H__

#include "parse.h"

#define HEAD_TOO_LAGER 1
#define HTTP_ERROR     2


class Http{
    char http_buff[HEADLENLIMIT];
    size_t http_getlen = 0;
    size_t http_expectlen;
    void HeaderProc();
    void ChunkLProc();
    void ChunkBProc();
    void FixLenProc();
    void AlwaysProc();
protected:
    bool ignore_body = false;
    virtual ssize_t Read(void* buff, size_t len) = 0;
    virtual void ErrProc(int errcode) = 0;
    virtual void ReqProc(HttpReqHeader &req);
    virtual void ResProc(HttpResHeader &res);
    virtual ssize_t DataProc(const void *buff, size_t size) = 0;
public:
    explicit Http(bool transparent = false);
    void (Http::*Http_Proc)();
};

#endif
