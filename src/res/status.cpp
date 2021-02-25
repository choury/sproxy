#include "status.h"
#include "misc/net.h"
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

void Status::request(HttpReq* req, Requester* src){
    if(!checkauth(src->getip())){
        req->response(new HttpRes(new HttpResHeader(H401), ""));
    }else{
        HttpResHeader* header = new HttpResHeader(H200);
        header->set("Transfer-Encoding", "chunked");
        header->set("Content-Type", "text/plain; charset=utf8");
        HttpRes* res = new HttpRes(header);
        req->response(res);
        ::dump_stat(StatusDump, res);
        res->send((const void*)nullptr, 0);
    }
    deleteLater(PEER_LOST_ERR);
}

void Status::dump_stat(Dumper dp, void* param){
    dp(param, "status: %p\n", this);
}
