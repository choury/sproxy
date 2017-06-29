#include "host.h"
#include "req/requester.h"
#include "misc/job.h"

#include <assert.h>
                    
void Host::con_timeout(Host* host) {
    del_job((job_func)con_timeout, host);
    LOGE("connect to %s time out.\n", host->hostname);
    host->deleteLater(CONNECT_TIMEOUT);
}

Host::Host(const char* hostname, uint16_t port, Protocol protocol): port(port), protocol(protocol){
    assert(port);
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}

Host::~Host(){
    del_job((job_func)con_timeout, this);
}


void Host::Dnscallback(Host* host, const char *hostname, std::list<sockaddr_un> addrs) {
    host->testedaddr = 0;
    if (addrs.size() == 0) {
        LOGE("Dns query failed: %s\n", hostname);
        host->deleteLater(DNS_FAILED);
    } else {
        for (auto i: addrs){
            host->addrs.push_back(i);
            host->addrs.back().addr_in6.sin6_port = htons(host->port);
        }
        host->connect();
        add_job((job_func)con_timeout, host, 60000);
    }
}

int Host::connect() {
    if ((size_t)testedaddr>= addrs.size()) {
        return -1;
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
        if(reqs.size()){
            updateEpoll(EPOLLOUT);
            handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        }else{
            deleteLater(PEER_LOST_ERR);
        }
        return 0;
    }
}


void Host::waitconnectHE(uint32_t events) {
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
        del_job((job_func)con_timeout, this);
    }
    return;
reconnect:
    if (connect() < 0) {
        deleteLater(CONNECT_FAILED);
    }
}

ssize_t Host::Write_buff() {
    ssize_t ret = 0;
    for(auto& req:reqs){
        if(req.size() == 0){
            continue;
        }
        if(req.header_buff == nullptr && !req.header->should_proxy){
            if(req.header->ismethod("CONNECT")){
                Http_Proc = &Host::AlwaysProc;
                HttpResHeader* res = new HttpResHeader(H200);
                HttpReq& req = reqs.front();
                res->index = req.header->index;
                req.header->src->response(res);
            }else if(req.header->ismethod("SEND")){
                Http_Proc = &Host::AlwaysProc;
            }
        }
        ret = req.Write_string([this](const void *buff, size_t size){
            return Write(buff, size);
        });
        if(ret <= 0){
            break;
        }else{
            req.header->src->writedcb(req.header->index);
        }
    }
    return ret;
}


void Host::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): host error: %s\n", hostname, strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = Write_buff();
        if(ret < 0 && showerrinfo(ret, "host write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(reqs.empty() || reqs.back().size()==0){
            updateEpoll(EPOLLIN);
        }
    }
}


void* Host::request(HttpReqHeader* req) {
    assert(Http_Proc != &Host::AlwaysProc);

    reqs.push_back(req);
    updateEpoll(events | EPOLLOUT);
    return reinterpret_cast<void*>(1);
}

int32_t Host::bufleft(void*) {
    size_t len = 0;
    for(auto& req: reqs){
        len += req.size();
    }
    return 1024*1024 - len;
}


ssize_t Host::Send(void* buff, size_t size, void* index) {
    assert((long)index == 1);
    reqs.back().body.push(buff, size);
    updateEpoll(events | EPOLLOUT);
    return size;
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


ssize_t Host::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Host::ResProc(HttpResHeader* res) {
    if(reqs.empty()){
        deleteLater(PEER_LOST_ERR);
        delete res;
        return;
    }
    if(reqs.front().header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    HttpReq& req = reqs.front();
    res->index = req.header->index;
    req.header->src->response(res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    if(reqs.empty()){
        deleteLater(PEER_LOST_ERR);
        return -1;
    }

    HttpReq& req = reqs.front();
    int len = req.header->src->bufleft(req.header->index);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full (%s)\n",
             req.header->src->getsrc(req.header->index), req.header->hostname);
        updateEpoll(0);
        return -1;
    }
    return req.header->src->Send(buff, Min(size, len), req.header->index);
}

void Host::EndProc() {
    HttpReq& req = reqs.front();
    req.header->src->finish(NOERROR, req.header->index);
    reqs.pop_front();
    if(reqs.empty()){
        deleteLater(NOERROR);
    }
}


void Host::ErrProc(int errcode) {
    if(errcode == 0 && reqs.size()){
        HttpReq& req = reqs.front();
        req.header->src->finish(NOERROR, req.header->index);
        reqs.pop_front();
    }
    if(showerrinfo(errcode, "Host-http error")) {
        deleteLater(HTTP_PROTOCOL_ERR);
    }
}

void Host::finish(uint32_t errcode, void* index) {
    assert((long)index == 1);
    if(errcode){
        reqs.clear();
        if(testedaddr >= 0){
            Peer::deleteLater(errcode);
        }
    }
}

void Host::deleteLater(uint32_t errcode){
    for(auto& req: reqs){
        if(!req.header->ismethod("SEND")){
            if(errcode == CONNECT_TIMEOUT || errcode == DNS_FAILED){
                HttpResHeader* res = new HttpResHeader(H504);
                res->index = req.header->index;
                req.header->src->response(res);
            }else if(errcode == CONNECT_FAILED){
                HttpResHeader* res = new HttpResHeader(H503);
                res->index = req.header->index;
                req.header->src->response(res);
            }
        }
        req.header->src->finish(errcode, req.header->index);
    }
    reqs.clear();
    if(testedaddr >= 0){
        Peer::deleteLater(errcode);
    }
}

void Host::dump_stat() {
    LOG("Host %p, <%s> (%s:%d):\n", this, protstr(protocol), hostname, port);
    for(auto& req: reqs){
        LOG("    %s %s: %p, %p\n",
            req.header->method, req.header->geturl().c_str(),
            req.header->src, req.header->index);
    }
}
