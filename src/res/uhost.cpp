#include "uhost.h"
#include "prot/netio.h"
#include "prot/memio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Uhost::Uhost(const Destination& dest): port(dest.port) {
    strncpy(hostname, dest.hostname, DOMAINLIMIT);
    idle_timeour = AddJob([this]{deleteLater(CONNECT_AGED);}, 30000, 0);
    cb = ISocketCallback::create()->onConnect([this](const sockaddr_storage&, uint32_t){
        LOGD(DHTTP, "<uhost> %s connected\n", dumpDest(rwer->getDst()).c_str());
        status.rw->SetCallback(status.cb);
    })->onRead([this](Buffer&& bb) -> size_t{
        if(JobPending(idle_timeour) < 30000 || JobPending(idle_timeour) == UINT32_MAX) {
            idle_timeour = UpdateJob(std::move(idle_timeour), [this]{deleteLater(CONNECT_AGED);}, 30000);
        }
        LOGD(DHTTP, "<uhost> (%s) read: len:%zu, refs: %zd\n", dumpDest(rwer->getDst()).c_str(), bb.len, bb.refs());
        if(!is_responsed){
            status.rw->SendHeader(HttpResHeader::create(S200, sizeof(S200), status.req->request_id));
            is_responsed = true;
        }
        size_t len = bb.len;
        int cap = status.rw->cap(bb.id);
        if (cap < (int)bb.len) {
            LOGE("[%" PRIu64 "]: <uhost> the res buff is full (%d vs %d) [%s], drop it\n",
                 status.req->request_id, cap, (int)bb.len,
                 status.req->geturl().c_str());
            rx_dropped += bb.len;
            return 0;
        } else {
            rx_bytes += bb.len;
            status.rw->Send(std::move(bb));
            return len;
        }
    })->onWrite([this](uint64_t id){
        idle_timeour = UpdateJob(std::move(idle_timeour), [this]{deleteLater(CONNECT_AGED);}, 120000);
        LOGD(DHTTP, "<uhost> (%s) written\n", dumpDest(rwer->getDst()).c_str());
        status.rw->Unblock(id);
    })->onError([this](int ret, int code){
        LOGE("(%s) UDP error: %d/%d\n", dumpDest(rwer->getDst()).c_str(), ret, code);
        deleteLater(ret);
    });
    rwer = std::make_shared<PacketRWer>(dest, cb);
}

Uhost::Uhost(std::shared_ptr<HttpReqHeader> req):
    Uhost(req->Dest)
{
}

Uhost::~Uhost() {
    if(rwer){
        LOGD(DHTTP, "<uhost> (%s) destoryed: rx:%zu, tx:%zu, drop: %zu\n",
             dumpDest(rwer->getDst()).c_str(), rx_bytes, tx_bytes, rx_dropped);
    }else{
        LOGD(DHTTP, "<uhost> null destoryed: rx:%zu, tx:%zu, drop: %zu\n",
             rx_bytes, tx_bytes, rx_dropped);
    }
}

void Uhost::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    LOGD(DHTTP, "<uhost> request %" PRIu64 ": %s\n",
         req->request_id, req->geturl().c_str());
    status.req = req;
    status.rw = rw;
    status.cb = IRWerCallback::create()->onRead([this](Buffer&& bb) -> size_t{
        LOGD(DHTTP, "<uhost> Recv %d: %zu bytes, refs: %zd\n",
                (int)status.req->request_id, bb.len, bb.refs());
        if (bb.len == 0) {
            return 0;
        }
        auto len = bb.len;
        tx_bytes += len;
        rwer->Send(std::move(bb));
        return len;
    })->onWrite([this](uint64_t id){
        rwer->Unblock(id);
    })->onError([this](int, int){
        LOGD(DHTTP, "<uhost> signal %d error\n", (int)status.req->request_id);
        is_closing = true;
        deleteLater(PEER_LOST_ERR);
        return 0;
    });
}

void Uhost::deleteLater(uint32_t errcode) {
    status.rw->SetCallback(nullptr);
    if(is_closing || is_responsed){
        //do nothing
    }else {
        uint64_t id = status.req->request_id;
        switch(errcode) {
        case DNS_FAILED:
            response(status.rw, HttpResHeader::create(S503, sizeof(S503), id), "[[dns failed]]\n");
            break;
        case CONNECT_FAILED:
            response(status.rw, HttpResHeader::create(S503, sizeof(S503), id), "[[connect failed]]\n");
            break;
        case SOCKET_ERR:
            response(status.rw, HttpResHeader::create(S502, sizeof(S502), id), "[[socket error]]\n");
            break;
        default:
            response(status.rw, HttpResHeader::create(S500, sizeof(S500), id), "[[internal error]]\n");
        }
    }
    status.rw->Close();
    is_closing = true;
    Server::deleteLater(errcode);
}

void Uhost::dump_stat(Dumper dp, void* param) {
    dp(param, "Uhost %p, tx:%zd, rx: %zd, drop: %zd\n  [%" PRIu64"]: %s %s, host: %s, port: %d\n",
       this, tx_bytes, rx_bytes, rx_dropped,
       status.req->request_id, status.req->method,
       dumpAuthority(&status.req->Dest),
       hostname, port);
    rwer->dump_status(dp, param);
}

void Uhost::dump_usage(Dumper dp, void *param) {
    if(status.rw) {
        dp(param, "Uhost %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), status.rw->mem_usage(), rwer->mem_usage());
    } else {
        dp(param, "Uhost %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
    }
}
