#include "ping.h"
#include "prot/tcpip/ip_pack.h"
#include "prot/netio.h"
#include "prot/memio.h"
#include "req/requester.h"
#include "misc/util.h"

#include <inttypes.h>
#include <assert.h>

Ping::Ping(const Destination& dest): id(dest.port?:random()&0xffff) {
    cb = ISocketCallback::create()->onConnect([this](const sockaddr_storage& addr, uint32_t){
        const sockaddr_in6 *addr6 = (const sockaddr_in6*)&addr;
        family = addr6->sin6_family;
        if(addr6->sin6_port == 0){
            flags |= PING_IS_RAW_SOCK;
        }
        status.rw->SetCallback(status.cb);
    })->onRead([this](Buffer&& bb) -> size_t{
        if((flags & PING_IS_RESPONSED) == 0){
            status.rw->SendHeader(HttpResHeader::create(S200, sizeof(S200), status.req->request_id));
            flags |= PING_IS_RESPONSED;
        }
        size_t len = bb.len;
        switch(family){
        case AF_INET:
            if(flags & PING_IS_RAW_SOCK){
                const ip* iphdr = (ip*)bb.mutable_data();
                size_t hlen = iphdr->ip_hl << 2;
                bb.reserve(sizeof(icmphdr) + hlen);
                status.rw->Send(std::move(bb));
            }else {
                bb.reserve(sizeof(icmphdr));
                status.rw->Send(std::move(bb));
            }
            break;
        case AF_INET6:
            bb.reserve(sizeof(icmp6_hdr));
            status.rw->Send(std::move(bb));
            break;
        default:
            abort();
        }
        return len;
    })->onError([this](int ret, int code){
        LOGE("(%s) Ping error: %d/%d\n", dumpDest(rwer->getDst()).c_str(), ret, code);
        deleteLater(ret);
    });
    rwer = std::make_shared<PacketRWer>(dest, cb);
}

void Ping::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    status.req = req;
    status.rw = rw;
    status.cb = IRWerCallback::create()->onRead([this](Buffer&& bb) -> size_t {
        LOGD(DVPN, "<ping> [%d] recv %zu bytes\n", id, bb.len);
        if(bb.len == 0){
            return 0;
        }
        auto len = bb.len;
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
        return len;
    })->onWrite([this](uint64_t id){
        rwer->Unblock(id);
    })->onError([this](int, int){
        LOGD(DVPN, "<ping> [%d] get error from req\n", this->id);
        flags |= PING_IS_CLOSED_F;
        deleteLater(PEER_LOST_ERR);
    });
}

void Ping::deleteLater(uint32_t errcode) {
    if(flags & PING_IS_CLOSED_F){
        //do nothing.
    }else if(status.rw && (flags & PING_IS_RESPONSED) == 0){
        status.rw->SetCallback(nullptr);
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
        status.rw->Close();
        status.rw = nullptr;
    }
    flags |= PING_IS_CLOSED_F;
    Server::deleteLater(errcode);
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "Ping %p, [%" PRIu64"]: %s %s, id: %d, seq: %d\n",
       this, status.req->request_id, status.req->method,
       dumpAuthority(&status.req->Dest),
       id, seq);
    rwer->dump_status(dp, param);
}

void Ping::dump_usage(Dumper dp, void *param) {
    if(status.rw) {
        dp(param, "Ping %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), status.rw->mem_usage(), rwer->mem_usage());
    } else {
        dp(param, "Ping %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
    }
}
