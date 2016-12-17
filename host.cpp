#include "host.h"
#include "requester.h"
#include "job.h"

#include <map>
#include <string.h>
#include <errno.h>
                    
void Host::con_timeout(Host* host) {
    LOGE("connect to %s time out.\n", host->hostname);
    host->clean(CONNECT_ERR, 0);
    del_job((job_func)con_timeout, host);
}

Host::Host(const char* hostname, uint16_t port, Protocol protocol): port(port), protocol(protocol){
    assert(port);
    memset(this->hostname, 0, sizeof(this->hostname));
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}

Host::~Host(){
    del_job((job_func)con_timeout, this);
}

void Host::discard() {
    requester_ptr = nullptr;
    Responser::discard();
}


void Host::Dnscallback(Host* host, const char *hostname, std::vector<sockaddr_un> addrs) {
    snprintf(host->hostname, sizeof(host->hostname), "%s", hostname);
    if (addrs.size() == 0) {
        LOGE("Dns query failed: %s\n", host->hostname);
        host->clean(CONNECT_ERR, 0);
    } else {
        host->addrs = addrs;
        for (size_t i = 0; i < host->addrs.size(); ++i) {
            host->addrs[i].addr_in6.sin6_port = htons(host->port);
        }
        host->connect();
    }
}

int Host::connect() {
    if (testedaddr>= addrs.size()) {
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
        add_job((job_func)con_timeout, this, 30000);
        if (fd < 0) {
            LOGE("connect to %s failed\n", this->hostname);
            return connect();
        }
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        return 0;
    }
}


void Host::waitconnectHE(uint32_t events) {
    if (requester_ptr == nullptr){
        clean(PEER_LOST_ERR, 0);
        return;
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): connect to %s error: %s\n", 
                 requester_ptr->getsrc(),  hostname, strerror(error));
        }
        goto reconnect;
    }
    
    if (events & EPOLLOUT) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("(%s): getsokopt error: %m\n", requester_ptr->getsrc());
            goto reconnect;
        }
        if (error != 0) {
            LOGE("(%s): connect to %s: %s\n", 
                 requester_ptr->getsrc(), this->hostname, strerror(error));
            goto reconnect;
        }
        updateEpoll(EPOLLIN | EPOLLOUT);

        if (http_flag & HTTP_CONNECT_F){
            HttpResHeader res(H200);
            res.http_id = requester_id;
            requester_ptr->response(std::move(res));
        }
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        del_job((job_func)con_timeout, this);
    }
    return;
reconnect:
    if (connect() < 0) {
        clean(CONNECT_ERR, 0);
    }
}

void Host::defaultHE(uint32_t events) {
    assert(requester_ptr && requester_id);

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): host error: %s\n", requester_ptr->getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, 0);
        return;
    }

    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = Peer::Write_buff();
        if (ret <= 0) {
            if (showerrinfo(ret, "host write error")) {
                clean(WRITE_ERR, 0);
            }
            return;
        }
        if(ret != WRITE_NOTHING && requester_ptr)
            requester_ptr->writedcb(requester_id);
    }
}


uint32_t Host::request(HttpReqHeader&& req) {
    size_t len;
    char *buff = req.getstring(len);
    Responser::Write(buff, len, 0);
    if(req.ismethod("CONNECT")){
        http_flag = HTTP_CONNECT_F;
        Http_Proc = &Host::AlwaysProc;
    }else if(req.ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }else if(req.ismethod("SEND")){
        Http_Proc = &Host::AlwaysProc;
    }
    requester_ptr = req.src;
    requester_id = req.http_id;
    assert(requester_ptr);
    assert(requester_id);
    return 1;
}

void Host::ResProc(HttpResHeader&& res) {
    assert(requester_ptr && requester_id);
    res.http_id = requester_id;
    requester_ptr->response(std::move(res));
}



Host* Host::gethost(HttpReqHeader& req, Responser* responser_ptr) {
    Protocol protocol = req.ismethod("SEND")?Protocol::UDP:Protocol::TCP;
    Host* host = dynamic_cast<Host *>(responser_ptr);
    if (host){
        if(strcasecmp(host->hostname, req.hostname) == 0
            && host->port == req.port
            && protocol == host->protocol
            && !req.ismethod("CONNECT"))
        {
            return host;
        }else{
            assert(host->requester_ptr == nullptr ||
                   host->requester_ptr == req.src);
        }
    }
    return new Host(req.hostname, req.port, protocol);
}


ssize_t Host::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Host::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Host-http error")) {
        clean(errcode, 0);
    }
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, 0);
        return -1;
    }

    int len = requester_ptr->bufleft(requester_id);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full\n", requester_ptr->getsrc());
        requester_ptr->wait(requester_id);
        updateEpoll(0);
        return -1;
    }

    return requester_ptr->Write(buff, Min(size, len), requester_id);
}

void Host::clean(uint32_t errcode, uint32_t id) {
    assert(id == 1 || id == 0);
    if(requester_ptr){
        if(errcode == CONNECT_ERR){
            HttpResHeader res(H408);
            res.http_id = requester_id;
            requester_ptr->response(std::move(res));
        }
        if(id == 0){
            requester_ptr->clean(errcode, requester_id);
        }
        requester_ptr = nullptr;
        requester_id = 0;
    }
    if(hostname[0]){
        Peer::clean(errcode, 0);
    }
}
