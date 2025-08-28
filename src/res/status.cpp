#include "status.h"
#include "misc/util.h"
#include "misc/strategy.h"
#include "req/requester.h"
#include "prot/memio.h"

#include <stdarg.h>
#include <assert.h>


Status::Status(){
}

static void StatusDump(void* param, const char* fmt, ...) {
    MemRWer* rw = (MemRWer *)param;
    size_t len;
    va_list ap;
    va_start(ap, fmt);
    char* buff = avsprintf(&len, fmt, ap);
    va_end(ap);
    rw->Send(Buffer{buff, len});
    free(buff);
}

void Status::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw){
    uint64_t id = req->request_id;
    if(!checkauth(rw->getSrc().hostname, req->get("Authorization"))){
        response(rw, HttpResHeader::create(S401, sizeof(S401), id), "");
    }else{
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S200, sizeof(S200), id);
        header->set("Transfer-Encoding", "chunked");
        header->set("Content-Type", "text/plain; charset=utf8");
        rw->SendHeader(header);
        ::dump_stat(StatusDump, rw.get());
        rw->Send(nullptr);
    }
    deleteLater(PEER_LOST_ERR);
}

void Status::dump_stat(Dumper dp, void* param){
    dp(param, "Status: %p\n", this);
}

void Status::dump_usage(Dumper dp, void *param) {
    dp(param, "Status %p: %zd\n", this, sizeof(*this));
}
