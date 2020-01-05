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
    HttpReqHeader* req = (HttpReqHeader *)param;
    size_t len;
    va_list ap;
    va_start(ap, fmt);
    char* buff = p_avsprintf(&len, fmt, ap);
    assert(!req->src.expired());
    req->src.lock()->Send(buff, len, req->index);
}

void* Status::request(HttpReqHeader* req){
    assert(!req->src.expired());
    auto req_ptr = req->src.lock();
    if(!checkauth(req_ptr->getip())){
        HttpResHeader* res = new HttpResHeader(H401, sizeof(H401));
        res->index = req->index;
        req_ptr->response(res);
    }else{
        HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
        res->set("Transfer-Encoding", "chunked");
        res->set("Content-Type", "text/plain; charset=utf8");
        res->index = req->index;
        req_ptr->response(res);
        ::dump_stat(StatusDump, req);
    }
    req_ptr->Send((const void*)nullptr, 0, req->index);
    return (void*)1;
}

void Status::Send(const void *, size_t, __attribute__ ((unused)) void* index){
    assert((long)index == 1);
}

void Status::Send(void *buff, size_t size, __attribute__ ((unused)) void* index){
    Send((const void*)buff, size, index);
    p_free(buff);
}

int32_t Status::bufleft(__attribute__ ((unused)) void* index){
    assert((long)index == 1);
    return 0;
}

int Status::finish(uint32_t flags, __attribute__ ((unused)) void* index){
    assert((long)index == 1);
    deleteLater(flags);
    return FINISH_RET_BREAK;
}

void Status::dump_stat(Dumper dp, void* param){
    dp(param, "status: %p\n", this);
}
