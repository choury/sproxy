#ifndef GZIP_TEST_H__
#define GZIP_TEST_H__

#include "responser.h"

#include <zlib.h>


class GzipTest: public Responser{
    z_stream strm;
    size_t left = 0;
    std::weak_ptr<Requester> req_ptr;
    void*      req_index;
public:
    GzipTest();
	virtual ~GzipTest() override;
    virtual void* request(HttpReqHeader* req) override;
    virtual void gzipreadHE(size_t len);
    virtual void rawreadHE(size_t len);

    virtual void Send(const void *buff, size_t size, void* index)override;
    virtual int32_t bufleft(void* index)override;
    virtual bool finish(uint32_t flags, void* index)override;
    virtual void dump_stat(Dumper dp, void* param)override;
};
#endif
