#ifndef HTTP_H__
#define HTTP_H__

#include "http_header.h"
#include "misc/buffer.h"

class HttpBase{
protected:
    uint64_t http_expectlen = 0;
#define HTTP_IGNORE_BODY_F          1u
#define HTTP_STATUS_1XX            (1u<<1u)
#define HTTP_CHUNK_END_F           (1u<<2u)
//#define HTTP_READ_CLOSE_F          (1u<<3u) //read from remote has been closed (<- guest <- host <-)
//#define HTTP_WRITE_CLOSE_F         (1u<<4u) //write to remote has been closed  (-> guest -> host ->)
    uint32_t http_flag = 0;
    virtual bool HeaderProc(Buffer& bb) = 0;
    bool ChunkLProc(Buffer& bb);
    bool ChunkBProc(Buffer& bb);
    bool FixLenProc(Buffer& bb);
    bool AlwaysProc(Buffer& bb);
    virtual void EndProc(uint64_t id) = 0;
    virtual void ErrProc(uint64_t id) = 0;
    virtual ssize_t DataProc(Buffer& bb) = 0;
public:
    bool (HttpBase::*Http_Proc)(Buffer& bb) = &HttpBase::HeaderProc;
};


class HttpResponser:public HttpBase{
protected:
    virtual bool HeaderProc(Buffer& bb)override final;
    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> req) = 0;
};

class HttpRequester:public HttpBase{
protected:
    virtual bool HeaderProc(Buffer& bb)override final;
    virtual void ResProc(uint64_t id, std::shared_ptr<HttpResHeader> res) = 0;
};

#endif
