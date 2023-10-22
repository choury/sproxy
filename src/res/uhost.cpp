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
                auto &bb = message.data;
                LOGD(DHTTP, "<uhost> Recv %d: %zu bytes\n", (int)req->header->request_id, bb.len);
                if (bb.len == 0) {
                    return 0;
                }
                rwer->buffer_insert(std::move(bb));
                return 1;
            }
            case ChannelMessage::CHANNEL_MSG_SIGNAL:
                LOGD(DHTTP, "<uhost> signal %d: %d\n", (int)req->header->request_id, message.signal);
                is_closing = true;
                deleteLater(PEER_LOST_ERR);
                return 0;
            }
            return 0;
        }, []{return BUF_LEN;});
    });
    rwer->SetReadCB([this](const Buffer& bb) -> size_t{
        if(res == nullptr){
            res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
            req->response(this->res);
        }
        res->send(Buffer{bb.data(), bb.len});
        return 0;
    });
}

Uhost::Uhost(std::shared_ptr<HttpReqHeader> req):
    Uhost(req->Dest.hostname, req->Dest.port)
{
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
        res->send(ChannelMessage::CHANNEL_ABORT);
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
    dp(param, "Uhost %p, [%" PRIu32"]: %s %s, host: %s, port: %d\n",
       this, req->header->request_id,
       req->header->method,
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
