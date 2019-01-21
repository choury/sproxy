#include "ping.h"
#include "prot/ip_pack.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/util.h"

#include <string.h>
#include <errno.h>
#include <assert.h>

Ping::Ping(const char* host, uint16_t id): id(id) {
    strcpy(hostname, host);
    assert(id);
    rwer = new PacketRWer(hostname, id, Protocol::ICMP, [this](int ret, int code){
        LOGE("Ping error: %d/%d\n", ret, code);
        iserror = true;
        if(ret == READ_ERR || ret == WRITE_ERR){
            deleteLater(ret);
        }
    },[this](const sockaddr_un* addr){
        seq = 1;
        this->addr = *addr;
    });
    rwer->SetReadCB([this](int len){
        const char* data = rwer->data();
        assert(!req_ptr.expired());
        switch(addr.addr.sa_family){
        case AF_INET:
            req_ptr.lock()->Send(data + sizeof(icmphdr), len - sizeof(icmphdr), req_index);
            break;
        case AF_INET6:
            req_ptr.lock()->Send(data + sizeof(icmp6_hdr), len - sizeof(icmp6_hdr), req_index);
            break;
        default:
            assert(0);
        }
        rwer->consume(data, len);
    });
}


Ping::Ping(HttpReqHeader* req):Ping(req->hostname, req->port) {
}

void* Ping::request(HttpReqHeader* req) {
    assert(req_ptr.expired() && req_index == nullptr);
    req_ptr = req->src;
    req_index = req->index;
    delete req;
    return (void *)(long)id;
}


void Ping::Send(void* buff, size_t size, __attribute__ ((unused)) void* index){
    assert(index == (void *)(long)id);
    if(iserror || seq == 0){
        return;
    }
    char* packet = (char*)buff;
    switch(addr.addr.sa_family){
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

void Ping::deleteLater(uint32_t errcode) {
    if(!req_ptr.expired()){
        req_ptr.lock()->finish(errcode, req_index);
        req_ptr = std::shared_ptr<Requester>();
    }
    return Peer::deleteLater(errcode);
}

void Ping::finish(uint32_t flags, __attribute__ ((unused)) void* index) {
    assert(index == (void *)(long)id);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        req_ptr = std::shared_ptr<Requester>();
        deleteLater(PEER_LOST_ERR);
    }
}

int32_t Ping::bufleft(__attribute__ ((unused)) void* index) {
    assert(index == (void *)(long)id);
    return 1024*1024;
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "ping %p, %s%s:(%d - %d) %p %p\n",
       this, iserror?"[E] ":"", hostname, id, seq, req_ptr.lock().get(), req_index);
}
