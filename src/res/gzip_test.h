#ifndef GZIP_TEST_H__
#define GZIP_TEST_H__

#include "responser.h"

#include <zlib.h>


class GzipTest: public Responser{
    z_stream strm;
    size_t left = 0;
    HttpReq* req = nullptr;
    HttpRes* res = nullptr;
    virtual void gzipreadHE(size_t len);
    virtual void rawreadHE(size_t len);
public:
    GzipTest();
	virtual ~GzipTest() override;
    virtual void request(HttpReq* req, Requester*) override;

    virtual void dump_stat(Dumper dp, void* param)override;
};
#endif
