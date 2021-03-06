#include "gzip_test.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/net.h"

#include <stdio.h>
#include <assert.h>

static unsigned char in[16384];

GzipTest::GzipTest() {
    rwer = new FullRWer([this](int ret, int code) {
        LOGE("gzip_test error: %d/%d\n", ret, code);
        res->trigger(Channel::CHANNEL_ABORT);
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

void GzipTest::request(HttpReq* req, Requester*) {
    req->setHandler([this](Channel::signal s){
        if(s == Channel::CHANNEL_SHUTDOWN){
            res->trigger(Channel::CHANNEL_ABORT);
        }
        deleteLater(PEER_LOST_ERR);
    });
    this->req = req;
    HttpResHeader *header = new HttpResHeader(H200, sizeof(H200));
    header->set("Content-Type", "application/octet-stream");
    header->set("Pragma", "no-cache");

    auto params = req->header->getparamsmap();
    if (params.count("size")) {
        left = parseSize(params["size"]);
    } else {
#if __LP64__
        left = 1024ull * 1024 * 1024 * 1024; //1T
#else
        left = 2ull * 1024 * 1024 * 1024;    //2G
#endif
    }

    const char *accept = req->header->get("Accept-Encoding");
    if (accept && strstr(accept, "gzip")) {
        header->set("Transfer-Encoding", "chunked");
        header->set("Content-Encoding", "gzip");
        rwer->SetReadCB(std::bind(&GzipTest::gzipreadHE, this, _1));
    } else {
        header->set("Content-Length", left);
        rwer->SetReadCB(std::bind(&GzipTest::rawreadHE, this, _1));
    }
    if (req->header->ismethod("HEAD")) {
        left = 0;
    }
    this->res = new HttpRes(header, std::bind(&RWer::EatReadData, rwer));
    req->response(this->res);
}

void GzipTest::gzipreadHE(size_t) {
    if (left == 0) {
        (void)deflateEnd(&strm);
        res->send((const void*)nullptr, 0);
        res->trigger(Channel::CHANNEL_CLOSED);
        deleteLater(NOERROR);
        rwer->delEvents(RW_EVENT::READ);
        return;
    }
    LOGD(DFILE, "gzip zip readHE\n");

    ssize_t chunk = res->cap();
    if(chunk <= 0){
        rwer->delEvents(RW_EVENT::READ);
        return;
    }

    unsigned char * out = (unsigned char*)malloc(chunk);
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

    res->send(out, chunk - strm.avail_out);
    free(out);
    if (strm.avail_out == 0) {
        rwer->delEvents(RW_EVENT::READ);
    }
}

void GzipTest::rawreadHE(size_t len) {
    if (left == 0) {
        (void)deflateEnd(&strm);
        res->send((const void*)nullptr, 0);
        res->trigger(Channel::CHANNEL_CLOSED);
        deleteLater(NOERROR);
        rwer->delEvents(RW_EVENT::READ);
        return;
    }

    LOGD(DFILE, "gzip raw readHE\n");
    ssize_t chunk = res->cap();
    if(chunk <= 0){
        rwer->delEvents(RW_EVENT::READ);
        return;
    }

    len = Min(chunk, left);
    unsigned char* const out = (unsigned char *)malloc(len);
    res->send(out, len);
    free(out);
    left -= len;
    if (left) {
        rwer->delEvents(RW_EVENT::READ);
    }
}

void GzipTest::dump_stat(Dumper dp, void *param) {
    dp(param, "gzip_test: %p left=%zu\n", this, left);
}
