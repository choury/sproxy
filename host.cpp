#include "host.h"
#include "requester.h"

#include <map>
#include <string.h>
#include <errno.h>
                    
std::map<Host*,time_t> connectmap;

void hosttick(void *) {
    for(auto i = connectmap.begin();i != connectmap.end();){
        Host *host = (Host *)(i->first);
        if(time(NULL) - i->second >= 30 && host->connect() < 0){
            connectmap.erase(i++);
            LOGE("connect to %s time out.\n", host->hostname);
            host->clean(CONNECT_ERR, host);
        }else{
            i++;
        }
    }
}

Host::Host(const char* hostname, uint16_t port, Protocol protocol): port(port), protocol(protocol){
    assert(port);
    memset(this->hostname, 0, sizeof(this->hostname));
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
    add_tick_func(hosttick, nullptr);
}

Host::~Host(){
    connectmap.erase(this);
}

void Host::ResetRequester(Requester* r) {
    requester_ptr = r;
}


void Host::discard() {
    requester_ptr = nullptr;
    Responser::discard();
}


void Host::Dnscallback(Host* host, const char *hostname, std::vector<sockaddr_un> addrs) {
    snprintf(host->hostname, sizeof(host->hostname), "%s", hostname);
    if (addrs.size() == 0) {
        LOGE("Dns query failed: %s\n", host->hostname);
        host->clean(CONNECT_ERR, host);
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
        connectmap[this]=time(NULL);
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
        clean(PEER_LOST_ERR, this);
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
            HttpResHeader res(H200, this);
            requester_ptr->response(res);
        }
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        connectmap.erase(this);
    }
    return;
reconnect:
    if (connect() < 0) {
        clean(CONNECT_ERR, this);
    }
}

void Host::defaultHE(uint32_t events) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): host error: %s\n", requester_ptr->getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }

    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = Write();
        if (ret <= 0) {
            if (showerrinfo(ret, "host write error")) {
                clean(WRITE_ERR, this);
            }
            return;
        }
        if(ret != WRITE_NOTHING)
            requester_ptr->writedcb(this);
    }
}


void Host::request(HttpReqHeader& req) {
    size_t len;
    char *buff = req.getstring(len);
    Write(buff, len, this);
    if(req.ismethod("CONNECT")){
        http_flag = HTTP_CONNECT_F;
        Http_Proc = &Host::AlwaysProc;
    }else if(req.ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }else if(req.ismethod("SEND")){
        Http_Proc = &Host::AlwaysProc;
    }
    requester_ptr = dynamic_cast<Requester *>(req.src);
}

void Host::ResProc(HttpResHeader& res) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }
    requester_ptr->response(res);
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
            host->request(req);
            return host;
        }else{
            assert(host->requester_ptr == nullptr ||
                   host->requester_ptr == dynamic_cast<Requester *>(req.src));
        }
    }
    if (responser_ptr) {
        responser_ptr->clean(NOERROR, dynamic_cast<Requester *>(req.src));
    }
    host = new Host(req.hostname, req.port, protocol);
    host->request(req);
    return host;
}


ssize_t Host::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Host::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Host-http error")) {
        clean(errcode, this);
    }
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, this);
        return -1;
    }

    int len = requester_ptr->bufleft(this);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full\n", requester_ptr->getsrc());
        requester_ptr->wait(this);
        return -1;
    }

    return requester_ptr->Write(buff, Min(size, len), this);
}

void Host::clean(uint32_t errcode, Peer* who, uint32_t) {
    assert(who);
    assert(dynamic_cast<Requester *>(who) == requester_ptr || who == this);
    if(requester_ptr){
        if(errcode == CONNECT_ERR){
            HttpResHeader res(H408, this);
            requester_ptr->response(res);
        }
        if(who == this){
            requester_ptr->clean(errcode, this);
        }
        requester_ptr = nullptr;
    }
    if(hostname[0]){
        Peer::clean(errcode, who);
    }
}
