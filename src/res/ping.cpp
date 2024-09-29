#include "ping.h"
#include "prot/tcpip/ip_pack.h"
#include "prot/netio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Ping::Ping(const char* host, uint16_t id): id(id?:random()&0xffff) {
    auto qrwer = std::make_shared<PacketRWer>(host, this->id, Protocol::ICMP, [this](int ret, int code){
        LOGE("(%s) Ping error: %d/%d\n", dumpDest(rwer->getDst()).c_str(), ret, code);
        deleteLater(ret);
    });
    rwer = qrwer;
    qrwer->SetConnectCB([this](const sockaddr_storage& addr){
        const sockaddr_in6 *addr6 = (const sockaddr_in6*)&addr;
        family = addr6->sin6_family;
        if(addr6->sin6_port == 0){
            flags |= PING_IS_RAW_SOCK;
        }
        req->attach([this](ChannelMessage&& message){
            switch(message.type){
            case ChannelMessage::CHANNEL_MSG_HEADER:
                LOGD(DVPN, "<ping> ignore header for req\n");
                return 1;
            case ChannelMessage::CHANNEL_MSG_DATA:
                Recv(std::move(std::get<Buffer>(message.data)));
                return 1;
            case ChannelMessage::CHANNEL_MSG_SIGNAL:
                LOGD(DVPN, "<ping> [%d] get signal from req: %d\n",
                     this->id, std::get<Signal>(message.data));
                flags |= PING_IS_CLOSED_F;
                deleteLater(PEER_LOST_ERR);
                return 0;
            }
            return 0;
        }, []{return BUF_LEN;});
    });
    rwer->SetReadCB([this](Buffer&& bb) -> size_t{
        if(res == nullptr){
            res = std::make_shared<HttpRes>(HttpResHeader::create(S200, sizeof(S200), req->header->request_id));
            req->response(this->res);
        }
        size_t len = bb.len;
        switch(family){
        case AF_INET:
            if(flags & PING_IS_RAW_SOCK){
                const ip* iphdr = (ip*)bb.mutable_data();
                size_t hlen = iphdr->ip_hl << 2;
                bb.reserve(sizeof(icmphdr) + hlen);
                res->send(std::move(bb));
            }else {
                bb.reserve(sizeof(icmphdr));
                res->send(std::move(bb));
            }
            break;
        case AF_INET6:
            bb.reserve(sizeof(icmp6_hdr));
            res->send(std::move(bb));
            break;
        default:
            abort();
        }
        return len;
    });
}


Ping::Ping(std::shared_ptr<HttpReqHeader> req):
    Ping(req->Dest.hostname, req->Dest.port)
{
}

void Ping::request(std::shared_ptr<HttpReq> req, Requester*) {
    this->req = req;
}


void Ping::Recv(Buffer&& bb){
    LOGD(DVPN, "<ping> [%d] recv %zu bytes\n", id, bb.len);
    if(bb.len == 0){
        return;
    }
    switch(family){
    case AF_INET:{
        Icmp icmp;
        icmp.settype(ICMP_ECHO)->setid(id+1)->setseq(seq++);
        icmp.build_packet(bb);
        break;}
    case AF_INET6:{
        Icmp6 icmp;
        icmp.settype(ICMP6_ECHO_REQUEST)->setid(id+1)->setseq(seq++);
        icmp.build_packet(nullptr, bb);
        break;}
    default:
        abort();
    }
    rwer->Send(std::move(bb));
}

void Ping::deleteLater(uint32_t errcode) {
    if(req){
        req->detach();
    }
    if(flags & PING_IS_CLOSED_F){
        //do nothing.
    }else if(res){
        res->send(CHANNEL_ABORT);
    }else {
        uint64_t id = req->header->request_id;
        switch(errcode) {
        case DNS_FAILED:
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S503, sizeof(S503), id),
                                                    "[[dns failed]]\n"));
            break;
        case CONNECT_FAILED:
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S503, sizeof(S503), id),
                                                    "[[connect failed]]\n"));
            break;
        case SOCKET_ERR:
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S502, sizeof(S502), id),
                                                    "[[socket error]]\n"));
            break;
        default:
            req->response(std::make_shared<HttpRes>(HttpResHeader::create(S500, sizeof(S500), id),
                                                    "[[internal error]]\n"));
        }
    }
    flags |= PING_IS_CLOSED_F;
    Server::deleteLater(errcode);
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "Ping %p, [%" PRIu64"]: %s %s, id: %d, seq: %d\n",
       this, req->header->request_id,
       req->header->method,
       dumpAuthority(&req->header->Dest),
       id, seq);
    rwer->dump_status(dp, param);
}

void Ping::dump_usage(Dumper dp, void *param) {
    if(res) {
        dp(param, "Ping %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), res->mem_usage(), rwer->mem_usage());
    } else {
        dp(param, "Ping %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
    }
}
