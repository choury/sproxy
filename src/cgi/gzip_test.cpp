//
// Created by choury on 4/6/24.
//
#include "res/cgi.h"
#include <zlib.h>

#include <thread>

static unsigned char in[CGI_LEN_MAX];

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


class handler: public CgiHandler {
    std::thread th;
    void GET(const CGI_Header*) override{
        if((flag.load(std::memory_order_acquire) & HTTP_REQ_COMPLETED) == 0){
            return;
        }
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(H200, sizeof(H200));
        res->set("Content-Type", "application/octet-stream");
        res->set("Pragma", "no-cache");
        Cookie cookie("sproxy", "gzip_test");
        res->addcookie(cookie);

        size_t left = 0;
        if (params.count("size")) {
            left = parseSize(params["size"]);
        } else {
#if __LP64__
            left = 1024ULL * 1024 * 1024 * 1024; //1T
#else
            left = 2ull * 1024 * 1024 * 1024;    //2G
#endif
        }

        const char *accept = req->get("Accept-Encoding");
        bool isgzip = false;
        if (accept && strstr(accept, "gzip")) {
            res->set("Transfer-Encoding", "chunked");
            res->set("Content-Encoding", "gzip");
            isgzip = true;
        } else {
            res->set("Content-Length", left);
        }
        if (req->ismethod("HEAD") || left == 0) {
            Response(res);
            Finish();
        } else if(isgzip) {
            z_stream* strm = new z_stream;
            /* allocate deflate state */
            strm->zalloc = Z_NULL;
            strm->zfree = Z_NULL;
            strm->opaque = Z_NULL;
            int ret;
            if ((ret = deflateInit2(strm, Z_BEST_SPEED, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY)) !=
                Z_OK) {
                LOGF("zlib init failed: %d\n", ret);
                Response(UnpackHttpRes(H500, sizeof(H500)));
                Finish();
                return;
            }
            Response(res);
            auto gzip_func = [this](z_stream* strm, size_t left) {
                auto buff = std::make_shared<Block>(CGI_LEN_MAX);
                while (left > 0 && (flag.load(std::memory_order_acquire) & HTTP_CLOSED_F) == 0){
                    strm->next_out = (unsigned char *) buff->data();
                    strm->avail_out = CGI_LEN_MAX;
                    /* run deflate() on input until output buffer not full, finish
                       compression if all source Has been read in */
                    do {
                        strm->next_in = in;
                        strm->avail_in = std::min(sizeof(in), left);
                        left -= strm->avail_in;
                        int ret = deflate(strm, left ? Z_NO_FLUSH : Z_FINISH);   /* no bad return value */
                        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
                        (void) ret;
                    } while (strm->avail_out && left);
                    Send((const char *) buff->data(), CGI_LEN_MAX - strm->avail_out);
                }
                (void) deflateEnd(strm);
                delete strm;
                Finish();
            };
            th = std::thread(gzip_func, strm, left);
        } else {
            Response(res);
            auto raw_func = [this](size_t left) {
                while (left > 0 && (flag.load(std::memory_order_acquire) & HTTP_CLOSED_F) == 0) {
                    size_t len = std::min(sizeof(in), left);
                    Send((const char *) in, len);
                    left -= len;
                }
                Finish();
            };
            th = std::thread(raw_func, left);
        }
    }
public:
    handler(int sfd, int cfd, const char* name, const CGI_Header* header):CgiHandler(sfd, -1, name, header){
        close(cfd);
    }
    ~handler(){
        if (th.joinable()) {
            th.join();
        }
    }
};

CGIMAIN(handler);

