#include "status.h"
#include "misc/net.h"
#include "misc/util.h"
#include "misc/strategy.h"
#include "req/requester.h"

#include <assert.h>
#include <stdarg.h>


Status::Status(){
}

static void StatusDump(void* param, const char* fmt, ...) {
    HttpReqHeader* req = (HttpReqHeader *)param;
    size_t len;
    va_list ap;
    va_start(ap, fmt);
    char* buff = p_avsprintf(&len, fmt, ap);
    req->src->Send(buff, len, req->index);
}

void* Status::request(HttpReqHeader* req){
    if(!checkauth(req->src->getip())){
        HttpResHeader* res = new HttpResHeader(H401, sizeof(H401));
        res->index = req->index;
        req->src->response(res);
    }else{
        HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
        res->set("Transfer-Encoding", "chunked");
        res->set("Content-Type", "text/plain; charset=utf8");
        res->index = req->index;
        req->src->response(res);
        ::dump_stat(StatusDump, req);
    }
    req->src->finish(NOERROR, req->index);
    return (void*)1;
}

ssize_t Status::Send(void *buff, size_t size, __attribute__ ((unused)) void* index){
    assert((long)index == 1);
    p_free(buff);
    return size;
}

int32_t Status::bufleft(__attribute__ ((unused)) void* index){
    assert((long)index == 1);
    return 0;
}

void Status::finish(uint32_t flags, __attribute__ ((unused)) void* index){
    assert((long)index == 1);
    if(flags){
        deleteLater(flags);
    }
}

void Status::dump_stat(Dumper dp, void* param){
    dp(param, "status: %p\n", this);
}
