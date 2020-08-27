#include "ping.h"
#include "prot/ip_pack.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/util.h"

#include <string.h>
#include <errno.h>
#include <assert.h>

Ping::Ping(const char* host, uint16_t id): id(id?id:random()&0xffff) {
    rwer = new PacketRWer(host, this->id, Protocol::ICMP, [this](int ret, int code){
        LOGE("Ping error: %d/%d\n", ret, code);
        iserror = true;
        if(rwer)
            rwer->setEvents(RW_EVENT::NONE);
    },[this](const sockaddr_un& addr){
        seq = 1;
        family = addr.addr.sa_family;
    });
    rwer->SetReadCB([this](int len){
        if(res == nullptr){
            res = new HttpRes(new HttpResHeader(H200));
            req->response(this->res);
        }
        const char* data = rwer->rdata();
        switch(family){
        case AF_INET:
            res->send(data + sizeof(icmphdr), len - sizeof(icmphdr));
            break;
        case AF_INET6:
            res->send(data + sizeof(icmp6_hdr), len - sizeof(icmp6_hdr));
            break;
        default:
            abort();
        }
        rwer->consume(data, len);
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
    req->attach(std::bind(&Ping::Send, this, _1, _2),[](){ return 1024*1024;});
}


void Ping::Send(void* buff, size_t size){
    if(iserror || seq == 0){
        return;
    }
    char* packet = (char*)buff;
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
    rwer->buffer_insert(rwer->buffer_end(), write_block{packet, size, 0});
}

/*
void Ping::deleteLater(uint32_t errcode) {
    if(req){
        req->body->trigger(Channel::CHANNEL_CLOSED);
        req = nullptr;
    }
    return Server::deleteLater(errcode);
}

int Ping::finish(uint32_t flags, __attribute__ ((unused)) void* index) {
    assert(index == (void *)(long)id);
    req_ptr = std::shared_ptr<Requester>();
    deleteLater(flags);
    return FINISH_RET_BREAK;
}

int32_t Ping::bufleft(__attribute__ ((unused)) void* index) {
    assert(index == (void *)(long)id);
}
 */

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "ping %p%s, id:%lu, <%s> (%s) (%d - %d)\n",
       this, iserror?" [E]":"", req->header->request_id, rwer->getDest(), rwer->getPeer(), id, seq);
}
