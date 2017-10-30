#include "ping.h"
#include "prot/dns.h"
#include "prot/ip_pack.h"
#include "req/requester.h"

#include <assert.h>

void Ping::Dnscallback(Ping* p, const char *hostname, std::list<sockaddr_un> addrs){
    if(addrs.size() == 0 ){
        LOGE("dns failed for ping\n");
        p->iserror = true;
        return;
    }
    for (auto i: addrs){
        i.addr_in6.sin6_port = 0;
        p->addrs.push_back(i);
    }
    p->fd = IcmpSocket(&p->addrs.front(), p->id);
    if(p->fd <= 0){
        LOGE("create icmp socket failed: %s\n", strerror(errno));
        p->iserror = true;
        return;
    }
    p->updateEpoll(EPOLLIN);
    p->handleEvent = (void (Con::*)(uint32_t))&Ping::defaultHE;
}

Ping::Ping(const char* host, uint16_t id): id(id) {
    strcpy(hostname, host);
    query(host, (DNSCBfunc)Dnscallback, this);
}


Ping::Ping(HttpReqHeader* req):Ping(req->hostname, req->port) {
}

void Ping::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            if(error){
                LOGE("(%s): ping error: %s\n", hostname, strerror(error));
            }
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLIN) {
        void* buff = p_malloc(BUF_LEN);
        int ret = Read(buff, BUF_LEN);
        if(ret <= 0 && showerrinfo(ret, "ping read")){
            deleteLater(READ_ERR);
        }else{
            req_ptr->Send(buff, ret, req_index);
        }
    }
}


void* Ping::request(HttpReqHeader* req) {
    req_ptr = req->src;
    req_index = req->index;
    delete req;
    return (void *)1;
}


ssize_t Ping::Send(void* buff, size_t size, void* index){
    assert(index == (void *)1);
    if(fd <= 0 || iserror){
        return size;
    }
    return Write(buff, size);
}

void Ping::deleteLater(uint32_t errcode) {
    if(req_ptr){
        req_ptr->finish(errcode, req_index);
        req_ptr = nullptr;
    }
    return Peer::deleteLater(errcode);
}

bool Ping::finish(uint32_t flags, void* index) {
    assert(index == (void *)1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode != VPN_AGED_ERR){
        req_ptr = nullptr;
        req_index = nullptr;
    }
    deleteLater(PEER_LOST_ERR);
    return false;
}



int32_t Ping::bufleft(void* index) {
    assert(index == (void *)1);
    return 1024*1024;
}

void Ping::dump_stat() {
    LOG("ping %p, %s%s:%d\n", this, iserror?"[E] ":"", hostname, id);
}
