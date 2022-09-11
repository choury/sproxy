#ifndef GZIP_TEST_H__
#define GZIP_TEST_H__

#include "responser.h"

#include <zlib.h>


class GzipTest: public Responser{
    z_stream strm;
    size_t left = 0;
    std::shared_ptr<HttpReq> req;
    std::shared_ptr<HttpRes> res;
    size_t gzipreadHE(uint64_t id, const void* data, size_t len);
    size_t rawreadHE(uint64_t id, const void* data, size_t len);
public:
    GzipTest();
	virtual ~GzipTest() override;
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;

    virtual void deleteLater(uint32_t error) override;
    virtual void dump_stat(Dumper dp, void* param)override;
    virtual void dump_usage(Dumper dp, void* param)override;
};
#endif
