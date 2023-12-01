#include "uhost.h"
#include "prot/netio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Uhost::Uhost(const char* host, uint16_t port): port(port) {
    strncpy(hostname, host, DOMAINLIMIT);
    auto prwer = std::make_shared<PacketRWer>(host, port, Protocol::UDP, [this](int ret, int code){
        LOGE("(%s) UDP error: %d/%d\n", rwer->getPeer(), ret, code);
        deleteLater(ret);
    });
    rwer = prwer;
    prwer->SetConnectCB([this](const sockaddr_storage&){
        LOGD(DHTTP, "<uhost> %s connected\n", rwer->getPeer());
        req->attach([this](ChannelMessage& message){
            switch(message.type){
            case ChannelMessage::CHANNEL_MSG_HEADER:
                LOGD(DHTTP, "<uhost> [%d] ignore header for req\n", (int)req->header->request_id);
                return 1;
            case ChannelMessage::CHANNEL_MSG_DATA: {
                auto &bb = std::get<Buffer>(message.data);
                LOGD(DHTTP, "<uhost> Recv %d: %zu bytes\n", (int)req->header->request_id, bb.len);
                if (bb.len == 0) {
                    return 0;
                }
                tx_bytes += bb.len;
                rwer->buffer_insert(std::move(bb));
                return 1;
            }
            case ChannelMessage::CHANNEL_MSG_SIGNAL:
                LOGD(DHTTP, "<uhost> signal %d: %d\n",
                     (int)req->header->request_id, std::get<Signal>(message.data));
                is_closing = true;
                deleteLater(PEER_LOST_ERR);
                return 0;
            }
            return 0;
        }, [this]{return rwer->cap(0);});
    });
    rwer->SetReadCB([this](Buffer bb) -> size_t{
        LOGD(DHTTP, "<uhost> (%s) read: len:%zu\n", rwer->getPeer(), bb.len);
        if(res == nullptr){
            res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
            req->response(this->res);
        }
        int len = res->cap();
        if (len < (int)bb.len) {
            LOGE("[%" PRIu32 "]: <uhost> the res buff is full (%d vs %d) [%s], drop it\n",
                 req->header->request_id,
                 len, (int)bb.len,
                 req->header->geturl().c_str());
            rx_dropped += bb.len;
        } else {
            rx_bytes += bb.len;
            res->send(std::move(bb));
        }
        return 0;
    });
    rwer->SetWriteCB([this](uint64_t){
        LOGD(DHTTP, "<uhost> (%s) written\n", rwer->getPeer());
        req->pull();
    });
}

Uhost::Uhost(std::shared_ptr<HttpReqHeader> req):
    Uhost(req->Dest.hostname, req->Dest.port)
{
}

Uhost::~Uhost() {
    if(rwer){
        LOGD(DHTTP, "<uhost> (%s) destoryed: rx:%zu, tx:%zu, drop: %zu\n",
             rwer->getPeer(), rx_bytes, tx_bytes, rx_dropped);
    }else{
        LOGD(DHTTP, "<uhost> null destoryed: rx:%zu, tx:%zu, drop: %zu\n",
             rx_bytes, tx_bytes, rx_dropped);
    }
}

void Uhost::request(std::shared_ptr<HttpReq> req, Requester*) {
    LOGD(DHTTP, "<uhost> request %" PRIu32 ": %s\n",
         req->header->request_id,
         req->header->geturl().c_str());
    this->req = req;
}

void Uhost::deleteLater(uint32_t errcode) {
    if(req){
        req->detach();
    }
    if(is_closing){
        //do nothing
    }else if(res){
        res->send(CHANNEL_ABORT);
    }else {
        switch(errcode) {
        case DNS_FAILED:
            req->response(std::make_shared<HttpRes>(UnpackHttpRes(H503), "[[dns failed]]\n"));
            break;
        case CONNECT_FAILED:
            req->response(std::make_shared<HttpRes>(UnpackHttpRes(H503), "[[connect failed]]\n"));
            break;
        case SOCKET_ERR:
            req->response(std::make_shared<HttpRes>(UnpackHttpRes(H502), "[[socket error]]\n"));
            break;
        default:
            req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[internal error]]\n"));
        }
    }
    is_closing = true;
    Server::deleteLater(errcode);
}

void Uhost::dump_stat(Dumper dp, void* param) {
    dp(param, "Uhost %p, tx:%zd, rx: %zd, drop: %zd\n  [%" PRIu32"]: %s %s, host: %s, port: %d\n",
       this, tx_bytes, rx_bytes, rx_dropped,
       req->header->request_id, req->header->method,
       dumpAuthority(&req->header->Dest),
       hostname, port);
    rwer->dump_status(dp, param);
}

void Uhost::dump_usage(Dumper dp, void *param) {
    if(res) {
        dp(param, "Uhost %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), res->mem_usage(), rwer->mem_usage());
    } else {
        dp(param, "Uhost %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
    }
}
