#include "host.h"
#include "req/requester.h"
#include "misc/job.h"

#include <assert.h>
                    
int Host::con_timeout(Host* host) {
    LOGE("connect to %s time out. retry...\n", host->hostname);
    host->connect();
    return 0;
}

Host::Host(const char* hostname, uint16_t port, Protocol protocol): port(port), protocol(protocol){
    assert(port);
    assert(protocol == Protocol::TCP || protocol == Protocol::UDP);
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}

Host::~Host(){
    assert(req == nullptr);
    del_delayjob((job_func)con_timeout, this);
}


void Host::Dnscallback(Host* host, const char *hostname, std::list<sockaddr_un> addrs) {
    host->testedaddr = 0;
    if (addrs.size() == 0) {
        LOGE("Dns query failed: %s\n", hostname);
        host->deleteLater(DNS_FAILED);
    } else {
        for (auto i: addrs){
            i.addr_in6.sin6_port = htons(host->port);
            host->addrs.push_back(i);
        }
        host->connect();
    }
}

void Host::connect() {
    if ((size_t)testedaddr>= addrs.size()) {
        deleteLater(PEER_LOST_ERR);
    } else {
        if (fd > 0) {
            updateEpoll(0);
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++], (int)protocol);
        if (fd < 0) {
            LOGE("connect to %s failed\n", hostname);
            return connect();
        }
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        add_delayjob((job_func)con_timeout, this, 30000);
    }
}


void Host::waitconnectHE(uint32_t events) {
    if (req == nullptr){
        return deleteLater(PEER_LOST_ERR);
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): host connect error: %s\n", hostname, strerror(error));
        }
        goto reconnect;
    }
    
    if (events & EPOLLOUT) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("(%s): getsokopt error: %s\n", hostname, strerror(errno));
            goto reconnect;
        }
        if (error != 0) {
            LOGE("(%s): connect error: %s\n",hostname, strerror(error));
            goto reconnect;
        }

        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        del_delayjob((job_func)con_timeout, this);
    }
    return;
reconnect:
    connect();
}

ssize_t Host::Write_buff() {
    if(req->header_buff == nullptr && !req->header->should_proxy){
        if(req->header->ismethod("CONNECT")){
            Http_Proc = &Host::AlwaysProc;
            HttpResHeader* res = new HttpResHeader(H200);
            res->index = req->header->index;
            req->header->src->response(res);
        }else if(req->header->ismethod("SEND")){
            Http_Proc = &Host::AlwaysProc;
        }
    }
    ssize_t ret = req->Write_string([this](const void *buff, size_t size){
        return Write(buff, size);
    });
    if(ret <= 0){
        return ret;
    }
    req->header->src->writedcb(req->header->index);
    return ret;
}

void Host::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            if(error){
                LOGE("(%s): host error: %s\n", hostname, strerror(error));
            }else if(req->header->ismethod("CONNECT")){
                EndProc();
                return;
            }
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLOUT) {
        int ret = Write_buff();
        if(ret < 0 && showerrinfo(ret, "host write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(req->size() == 0){
            updateEpoll(this->events & ~EPOLLOUT);
            if(http_flag & HTTP_CLIENT_CLOSE_F){
                shutdown(fd, SHUT_WR);
            }
        }
    }

    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }
}

void* Host::request(HttpReqHeader* req) {
    assert(Http_Proc != &Host::AlwaysProc);

    if(this->req){
        assert(req->src == this->req->header->src);
        delete this->req;
    }
    this->req =  new HttpReq(req);
    updateEpoll(events | EPOLLOUT);
    return reinterpret_cast<void*>(1);
}

int32_t Host::bufleft(void*) {
    return 1024*1024 - req->size();
}

ssize_t Host::Send(void* buff, size_t size, void* index) {
    assert((long)index == 1);
    req->body.push(buff, size);
    updateEpoll(events | EPOLLOUT);
    return size;
}

ssize_t Host::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Host::ResProc(HttpResHeader* res) {
    assert(req);
    if(req->header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    res->index = req->header->index;
    req->header->src->response(res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert(req);
    int len = req->header->src->bufleft(req->header->index);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full (%s)\n",
             req->header->src->getsrc(req->header->index), req->header->hostname);
        updateEpoll(0);
        return -1;
    }
    return req->header->src->Send(buff, Min(size, len), req->header->index);
}

bool Host::EndProc() {
    assert(req);
    if(!req->header->src->finish(NOERROR, req->header->index)){
        delete req;
        req = nullptr;
        Peer::deleteLater(PEER_LOST_ERR);
        return false;
    }
    return true;
}


void Host::ErrProc(int errcode) {
    if(errcode == 0 && req){
        http_flag |= HTTP_SERVER_CLOSE_F;
        if(!req->header->ismethod("CONNECT")){
            deleteLater(PEER_LOST_ERR);
        }else{
            updateEpoll(events & ~EPOLLIN);
        }
        return;
    }
    if(showerrinfo(errcode, "Host-http error")) {
        deleteLater(HTTP_PROTOCOL_ERR);
    }
}

bool Host::finish(uint32_t flags, void* index) {
    assert((long)index == 1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == VPN_AGED_ERR){
        deleteLater(errcode);
        return false;
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        delete req;
        req = nullptr;
        deleteLater(flags);
        return false;
    }
    if(req->header->ismethod("CONNECT")){
        http_flag |= HTTP_CLIENT_CLOSE_F;
        updateEpoll(events | EPOLLOUT);
    }
    return true;
}

void Host::deleteLater(uint32_t errcode){
    assert(errcode);
    if(req){
        if(!req->header->ismethod("SEND")){
            if(errcode == CONNECT_TIMEOUT || errcode == DNS_FAILED){
                HttpResHeader* res = new HttpResHeader(H504);
                res->index = req->header->index;
                req->header->src->response(res);
            }else if(errcode == CONNECT_FAILED){
                HttpResHeader* res = new HttpResHeader(H503);
                res->index = req->header->index;
                req->header->src->response(res);
            }
        }
        req->header->src->finish(errcode, req->header->index);
        delete req;
        req = nullptr;
    }
    if(testedaddr >= 0){
        Peer::deleteLater(errcode);
    }
}

void Host::writedcb(void* index) {
    if((http_flag & HTTP_SERVER_CLOSE_F) == 0){
        Peer::writedcb(index);
    }
}


Host* Host::gethost(HttpReqHeader* req, Responser* responser_ptr) {
    Protocol protocol = req->ismethod("SEND")?Protocol::UDP:Protocol::TCP;
    Host* host = dynamic_cast<Host *>(responser_ptr);
    if(req->ismethod("CONNECT") || req->ismethod("SEND")){
        return new Host(req->hostname, req->port, protocol);
    }
    if (host){
        if(strcasecmp(host->hostname, req->hostname) == 0
            && host->port == req->port
            && protocol == host->protocol)
        {
            return host;
        }
    }
    return new Host(req->hostname, req->port, protocol);
}


void Host::dump_stat() {
    LOG("Host %p, <%s> (%s:%d):\n", this, protstr(protocol), hostname, port);
    if(req){
        LOG("    %s %s: %p, %p\n",
            req->header->method, req->header->geturl().c_str(),
            req->header->src, req->header->index);
    }
}
