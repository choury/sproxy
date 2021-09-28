#include "status.h"
#include "misc/util.h"
#include "misc/strategy.h"
#include "req/requester.h"

#include <stdarg.h>
#include <assert.h>


Status::Status(){
}

static void StatusDump(void* param, const char* fmt, ...) {
    HttpRes* res = (HttpRes *)param;
    size_t len;
    va_list ap;
    va_start(ap, fmt);
    char* buff = avsprintf(&len, fmt, ap);
    va_end(ap);
    res->send(buff, len);
    free(buff);
}

void Status::request(std::shared_ptr<HttpReq> req, Requester* src){
    if(!checkauth(src->getid(), req->header->get("Authorization"))){
        req->response(std::make_shared<HttpRes>(UnpackHttpRes(H401), ""));
    }else{
        HttpResHeader* header = UnpackHttpRes(H200);
        header->set("Transfer-Encoding", "chunked");
        header->set("Content-Type", "text/plain; charset=utf8");
        auto res = std::make_shared<HttpRes>(header);
        req->response(res);
        ::dump_stat(StatusDump, res.get());
        res->send((const void*)nullptr, 0);
    }
    deleteLater(PEER_LOST_ERR);
}

void Status::dump_stat(Dumper dp, void* param){
    dp(param, "status: %p\n", this);
}
