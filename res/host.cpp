#include "host.h"
#include "req/requester.h"
#include "misc/job.h"

//#include <map>
//#include <string.h>
//#include <errno.h>
#include <assert.h>
                    
void Host::con_timeout(Host* host) {
    LOGE("connect to %s time out.\n", host->hostname);
    host->clean(CONNECT_TIMEOUT, 0);
    del_job((job_func)con_timeout, host);
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
        host->clean(DNS_FAILED, 0);
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
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        return 0;
    }
}


void Host::waitconnectHE(uint32_t events) {
    if (status.req_ptr == nullptr){
        clean(PEER_LOST_ERR, 0);
        return;
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

        if (http_flag & HTTP_CONNECT_F){
            HttpResHeader res(H200);
            res.index = status.req_index;
            status.req_ptr->response(std::move(res));
        }

        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        del_job((job_func)con_timeout, this);
    }
    return;
reconnect:
    if (connect() < 0) {
        clean(CONNECT_FAILED, 0);
    }
}

void Host::defaultHE(uint32_t events) {
    assert(status.req_ptr && status.req_index);

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): host error: %s\n", hostname, strerror(error));
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
        if(ret != WRITE_NOTHING && status.req_ptr)
            status.req_ptr->writedcb(status.req_index);
    }
}


void* Host::request(HttpReqHeader&& req) {
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
    status.req_ptr = req.src;
    status.req_index = req.index;
    assert(status.req_ptr);
    assert(status.req_index);
    strcpy(status.hostname, req.hostname);
    status.port = req.port;
    status.protocol = req.ismethod("SEND")?Protocol::UDP:Protocol::TCP;
    return reinterpret_cast<void*>(1);
}

void Host::ResProc(HttpResHeader&& res) {
    assert(status.req_ptr && status.req_index);
    res.index = status.req_index;
    status.req_ptr->response(std::move(res));
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
            assert(host->status.req_ptr == nullptr ||
                   host->status.req_ptr == req.src);
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
    if (status.req_ptr == NULL) {
        clean(PEER_LOST_ERR, 0);
        return -1;
    }

    int len = status.req_ptr->bufleft(status.req_index);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full (%s)\n", status.req_ptr->getsrc(), status.hostname);
//        status.req_ptr->wait(status.req_index);
        updateEpoll(0);
        return -1;
    }

    return status.req_ptr->Write(buff, Min(size, len), status.req_index);
}

void Host::clean(uint32_t errcode, void* index) {
    assert((long)index == 1 || (void*)index == 0);
    if(status.req_ptr){
        if(status.protocol == Protocol::TCP){
            if(errcode == CONNECT_TIMEOUT || errcode == DNS_FAILED){
                HttpResHeader res(H504);
                res.index = status.req_index;
                status.req_ptr->response(std::move(res));
            }else if(errcode == CONNECT_FAILED){
                HttpResHeader res(H503);
                res.index = status.req_index;
                status.req_ptr->response(std::move(res));
            }
        }
        if(index == nullptr || errcode == VPN_AGED_ERR){
            status.req_ptr->clean(errcode, status.req_index);
        }
        status.req_ptr = nullptr;
        status.req_index = nullptr;
    }
    if(testedaddr >= 0){
        Peer::clean(errcode, 0);
    }
}

void Host::dump_stat() {
    if(strcmp(hostname, status.hostname) == 0 && protocol == status.protocol && port == status.port){
        LOG("Host %p, <%s> (%s:%d): %p, %p\n", this, protstr(protocol),
            status.hostname, status.port, status.req_ptr, status.req_index);
    }else{
        LOG("Host %p [p], <%s> (%s:%d): %p, %p\n", this, protstr(protocol),
            status.hostname, status.port, status.req_ptr, status.req_index);
    }
}
