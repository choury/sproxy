#include "ping.h"
#include "prot/tcpip/ip_pack.h"
#include "prot/netio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Ping::Ping(const char* host, uint16_t id): id(id?:random()&0xffff) {
    rwer = std::make_shared<PacketRWer>(host, this->id, Protocol::ICMP, [this](int ret, int code){
        LOGE("(%s) Ping error: %d/%d\n", rwer->getPeer(), ret, code);
        if(res  == nullptr){
            res = std::make_shared<HttpRes>(UnpackHttpRes(H500));
            req->response(this->res);
        }
        rwer->setEvents(RW_EVENT::NONE);
    },[this](const sockaddr_storage& addr){
        const sockaddr_in6 *addr6 = (const sockaddr_in6*)&addr;
        family = addr6->sin6_family;
        if(addr6->sin6_port == 0){
            israw = true;
        }
        req->attach([this](ChannelMessage& message){
            switch(message.type){
            case ChannelMessage::CHANNEL_MSG_HEADER:
                LOGD(DVPN, "<ping> ignore header for req\n");
                return 1;
            case ChannelMessage::CHANNEL_MSG_DATA:
                Recv(std::move(message.data));
                return 1;
            case ChannelMessage::CHANNEL_MSG_SIGNAL:
                LOGD(DVPN, "<ping> [%d] get signal from req: %d\n", this->id, message.signal);
                this->req->detach();
                deleteLater(PEER_LOST_ERR);
                return 0;
            }
            return 0;
        }, []{return BUF_LEN;});
    });
    rwer->SetReadCB([this](uint64_t, const void* data, size_t len) -> size_t{
        if(res == nullptr){
            res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
            req->response(this->res);
        }
        Buffer bb{(char*)data, len};
        switch(family){
        case AF_INET:
            if(israw){
                const ip* iphdr = (ip*)data;
                size_t hlen = iphdr->ip_hl << 2;
                bb.reserve(sizeof(icmphdr) + hlen);
                res->send(std::move(bb));
            }else {
                bb.reserve(sizeof(icmphdr));
                res->send(std::move(bb));
            }
            break;
        case AF_INET6:
            if(israw){
                bb.reserve(sizeof(ip6_hdr) + sizeof(icmp6_hdr));
                res->send(std::move(bb));
            }else {
                bb.reserve(sizeof(icmp6_hdr));
                res->send(std::move(bb));
            }
            break;
        default:
            abort();
        }
        return 0;
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
        icmp.settype(ICMP_ECHO)->setid(id)->setseq(seq++);
        icmp.build_packet(bb);
        break;}
    case AF_INET6:{
        Icmp6 icmp;
        icmp.settype(ICMP6_ECHO_REQUEST)->setid(id)->setseq(seq++);
        icmp.build_packet(nullptr, bb);
        break;}
    default:
        abort();
    }
    rwer->buffer_insert(rwer->buffer_end(), std::move(bb));
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "ping %p, [%" PRIu32"], id: %d, seq: %d\n",
       this, req->header->request_id, id, seq);
    rwer->dump_status(dp, param);
}
