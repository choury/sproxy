#ifndef GZIP_TEST_H__
#define GZIP_TEST_H__

#include "responser.h"

#include <zlib.h>


class GzipTest: public Responser{
    z_stream strm;
    size_t left = 0;
    HttpReq* req = nullptr;
    HttpRes* res = nullptr;
    virtual void gzipreadHE(buff_block&);
    virtual void rawreadHE(buff_block&);
public:
    GzipTest();
	virtual ~GzipTest() override;
    virtual void request(HttpReq* req, Requester*) override;

    virtual void dump_stat(Dumper dp, void* param)override;
};
#endif
