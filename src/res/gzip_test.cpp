#include "gzip_test.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/util.h"
#include "misc/net.h"

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

static unsigned char in[16384];

GzipTest::GzipTest() {
    rwer = new EventRWer([this](int ret, int code) {
        LOGE("gzip_test error: %d/%d\n", ret, code);
        deleteLater(ret);
    });

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int ret;
    if ((ret = deflateInit2(&strm, Z_BEST_SPEED, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY)) != Z_OK) {
        LOGE("zlib init failed: %d\n", ret);
        throw 0;
    }

}

GzipTest::~GzipTest(){
}

static size_t parseSize(std::string size) {
    if (size.empty() || !isdigit(size[0])) {
        return 0;
    }
    size_t num = stoull(size);
    size_t unitPos = std::string::npos;
    for (size_t i = 0; i < size.size(); i++) {
        if (!isdigit(size[i])) {
            unitPos = i;
            break;
        }
    }
    if (unitPos == std::string::npos) {
        return num;
    }
    std::string unit = size.substr(unitPos);
    switch (unit[0]) {
    case 'k':
    case 'K':
        return num * 1024;
    case 'm':
    case 'M':
        return num * 1024 * 1024;
    case 'g':
    case 'G':
        return num * 1024 * 1024 * 1024;
    case 't':
    case 'T':
        return num * 1024 * 1024 * 1024 * 1024;
    }
    return 0;
}

void *GzipTest::request(HttpReqHeader *req) {
    HttpResHeader *res = new HttpResHeader(H200, sizeof(H200));
    res->set("Content-Type", "application/octet-stream");
    res->set("Pragma", "no-cache");
    res->index = req->index;

    auto params = req->getparamsmap();
    if (params.count("size")) {
        left = parseSize(params["size"]);
    } else {
#if __LP64__
        left = 1024ull * 1024 * 1024 * 1024; //1T
#else
        left = 2ull * 1024 * 1024 * 1024;    //4G
#endif
    }
    const char *accept = req->get("Accept-Encoding");
    if (accept && strstr(accept, "gzip")) {
        res->set("Transfer-Encoding", "chunked");
        res->set("Content-Encoding", "gzip");
        rwer->SetReadCB(std::bind(&GzipTest::gzipreadHE, this, _1));
    } else {
        res->set("Content-Length", left);
        rwer->SetReadCB(std::bind(&GzipTest::rawreadHE, this, _1));
    }
    req->src.lock()->response(res);
    req_ptr = req->src;
    req_index = req->index;
    if (req->ismethod("HEAD")) {
        left = 0;
    }else{
        rwer->buffer_insert(rwer->buffer_end(), write_block{p_memdup(&left, 8), 8, 0});
    }
    return (void *)1;
}

void GzipTest::gzipreadHE(size_t len) {
    rwer->consume(nullptr, len);
    rwer->buffer_insert(rwer->buffer_end(), write_block{p_memdup(&left, 8), 8, 0});

    assert(!req_ptr.expired());
    if (left == 0) {
        (void)deflateEnd(&strm);
        req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, req_index);
        deleteLater(NOERROR);
        return;
    }

    ssize_t chunk = req_ptr.lock()->bufleft(req_index);
    if(chunk <= 0){
        rwer->delEvents(RW_EVENT::READ);
        return;
    }

    unsigned char* const out = (unsigned char *)p_malloc(chunk);
    strm.next_out = out;
    strm.avail_out = chunk;
    /* run deflate() on input until output buffer not full, finish
       compression if all of source has been read in */
    do {
        strm.next_in = in;
        strm.avail_in = Min(sizeof(in), left);
        left -= strm.avail_in;
        int ret = deflate(&strm, left ? Z_NO_FLUSH : Z_FINISH);   /* no bad return value */
        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
    } while (strm.avail_out && left);

    req_ptr.lock()->Send(out, chunk - strm.avail_out, req_index);
    if (strm.avail_out == 0) {
        rwer->delEvents(RW_EVENT::READ);
    }
}

void GzipTest::rawreadHE(size_t len) {
    rwer->consume(nullptr, len);
    rwer->buffer_insert(rwer->buffer_end(), write_block{p_memdup(&left, 8), 8, 0});

    assert(!req_ptr.expired());
    if (left == 0) {
        (void)deflateEnd(&strm);
        req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, req_index);
        deleteLater(NOERROR);
        return;
    }

    ssize_t chunk = req_ptr.lock()->bufleft(req_index);
    if(chunk <= 0){
        rwer->delEvents(RW_EVENT::READ);
        return;
    }

    len = Min(chunk, left);
    unsigned char* const out = (unsigned char *)p_malloc(len);
    req_ptr.lock()->Send(out, len, req_index);
    left -= len;
    if (left) {
        rwer->delEvents(RW_EVENT::READ);
    }
}

void GzipTest::Send(const void*, size_t , __attribute__((unused)) void *index) {
    assert((long)index == 1);
}

int32_t GzipTest::bufleft(__attribute__((unused)) void *index) {
    assert((long)index == 1);
    return 0;
}

void GzipTest::finish(uint32_t flags, __attribute__((unused)) void *index) {
    assert((long)index == 1);
    if (flags) {
        (void)deflateEnd(&strm);
        deleteLater(flags);
    }
}

void GzipTest::dump_stat(Dumper dp, void *param) {
    dp(param, "gzip_test: %p left=%zu\n", this, left);
}
