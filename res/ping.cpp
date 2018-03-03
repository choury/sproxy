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
    rwer = new PacketRWer(hostname, id, Protocol::ICMP, [this](int ret, int code){
        LOGE("Ping error: %d/%d\n", ret, code);
        iserror = true;
        if(ret == READ_ERR || ret == WRITE_ERR){
            deleteLater(ret);
        }
    });
    rwer->SetReadCB([this](int len){
        const char* data = rwer->data();
        req_ptr->Send(data, len, req_index);
        rwer->consume(data, len);
    });
}


Ping::Ping(HttpReqHeader* req):Ping(req->hostname, req->port) {
}

void* Ping::request(HttpReqHeader* req) {
    req_ptr = req->src;
    req_index = req->index;
    delete req;
    return (void *)1;
}


ssize_t Ping::Send(void* buff, size_t size, __attribute__ ((unused)) void* index){
    assert(index == (void *)1);
    if(iserror){
        return size;
    }
    return rwer->buffer_insert(rwer->buffer_end(), buff, size);
}

void Ping::deleteLater(uint32_t errcode) {
    if(req_ptr){
        req_ptr->finish(errcode, req_index);
        req_ptr = nullptr;
    }
    return Peer::deleteLater(errcode);
}

void Ping::finish(uint32_t flags, __attribute__ ((unused)) void* index) {
    assert(index == (void *)1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode != VPN_AGED_ERR){
        req_ptr = nullptr;
        req_index = nullptr;
    }
    if(errcode && (flags & DISCONNECT_FLAG)){
        deleteLater(PEER_LOST_ERR);
    }
}



int32_t Ping::bufleft(__attribute__ ((unused)) void* index) {
    assert(index == (void *)1);
    return 1024*1024;
}

void Ping::dump_stat(Dumper dp, void* param) {
    dp(param, "ping %p, %s%s:%d\n", this, iserror?"[E] ":"", hostname, id);
}
