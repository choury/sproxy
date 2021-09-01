#include "ping.h"
#include "prot/ip_pack.h"
#include "prot/netio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Ping::Ping(const char* host, uint16_t id): id(id?id:random()&0xffff) {
    rwer = new PacketRWer(host, this->id, Protocol::ICMP, [this](int ret, int code){
        LOGE("Ping error: %d/%d\n", ret, code);
        rwer->setEvents(RW_EVENT::NONE);
        req->attach((Channel::recv_const_t)[](const void*, size_t){},[](){ return 1024*1024;});
    },[this](const sockaddr_storage& addr){
        const sockaddr_in6 *addr6 = (const sockaddr_in6*)&addr;
        family = addr6->sin6_family;
        if(addr6->sin6_port == 0){
            israw = true;
        }
        req->attach(std::bind(&Ping::Send, this, _1, _2),[](){ return 1024*1024;});
    });
    rwer->SetReadCB([this](buff_block& bb){
        if(res == nullptr){
            res = new HttpRes(UnpackHttpRes(H200));
            req->response(this->res);
        }
        assert(bb.offset == 0);
        const char* data = (const char*)bb.buff;
        switch(family){
        case AF_INET:
            if(israw){
                const ip* iphdr = (ip*)data;
                size_t hlen = iphdr->ip_hl << 2;
                res->send(data  + hlen + sizeof(icmphdr), bb.len - hlen - sizeof(icmphdr));
            }else {
                res->send(data + sizeof(icmphdr), bb.len - sizeof(icmphdr));
            }
            break;
        case AF_INET6:
            if(israw){
                res->send(data + sizeof(ip6_hdr) + sizeof(icmp6_hdr), bb.len - sizeof(ip6_hdr) - sizeof(icmp6_hdr));
            }else {
                res->send(data + sizeof(icmp6_hdr), bb.len - sizeof(icmp6_hdr));
            }
            break;
        default:
            abort();
        }
        bb.offset = bb.len;
    });
}


Ping::Ping(HttpReqHeader* req):Ping(req->Dest.hostname, req->Dest.port) {
}

void Ping::request(HttpReq* req, Requester*) {
    this->req = req;
    req->setHandler([this](Channel::signal s){
        if(s == Channel::CHANNEL_SHUTDOWN){
            res->trigger(Channel::CHANNEL_ABORT);
        }
        deleteLater(PEER_LOST_ERR);
    });
}


void Ping::Send(void* buff, size_t size){
    char* packet;
    switch(family){
    case AF_INET:{
        Icmp icmp;
        icmp.settype(ICMP_ECHO)->setid(id)->setseq(seq++);
        packet = icmp.build_packet(buff, size);
        break;}
    case AF_INET6:{
        Icmp6 icmp;
        icmp.settype(ICMP6_ECHO_REQUEST)->setid(id)->setseq(seq++);
        packet = icmp.build_packet(nullptr, buff, size);
        break;}
    default:
        abort();
    }
    rwer->buffer_insert(rwer->buffer_end(), buff_block{packet, size});
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "ping %p, id:%" PRIu32 ", (%s) (%d - %d)\n",
       this, req->header->request_id, rwer->getPeer(), id, seq);
}
