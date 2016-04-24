#ifdef CLIENT
#include "proxy.h"
#else
#include "host.h"
#endif

#include <map>
#include <string.h>
#include <errno.h>
                    
std::map<Host*,time_t> connectmap;

Host::Host(HttpReqHeader& req, Guest* guest):Peer(0), req(req) {
    ::connect(guest, this);
    Request(guest, req);
    snprintf(hostname, sizeof(hostname), "%s", req.hostname);
    port = req.port;
    if(req.ismethod("CONNECT")){
        Http_Proc = &Host::AlwaysProc;
    }else if(req.ismethod("SEND")){
        Http_Proc = &Host::AlwaysProc;
        udp_mode = true;
    }
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}


Host::Host(HttpReqHeader &req, Guest* guest, const char* hostname, uint16_t port):Peer(0), req(req) {
    ::connect(guest, this);
    Request(guest, req);
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);
    this->port = port;
    if(req.ismethod("CONNECT") || req.ismethod("SEND")){
        Http_Proc = &Host::AlwaysProc;
    }   
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}


int Host::showerrinfo(int ret, const char* s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("%s: %s\n", s, strerror(errno));
        } else {
            return 0;
        }
    }else if(ret){
        LOGE("%s:%d\n",s, ret);
    }
    return 1;
}


void Host::waitconnectHE(uint32_t events) {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == nullptr) {
        destory();
        return;
    }
    
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("connect to host error: %s\n", strerror(error));
        }
        goto reconnect;
    }
    
    if (events & EPOLLOUT) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("getsokopt error: %s\n", strerror(error));
            goto reconnect;
        }
        if (error != 0) {
            LOGE("connect to %s: %s\n", this->hostname, strerror(error));
            goto reconnect;
        }
        
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        if (req.ismethod("CONNECT")) {
            HttpResHeader res(connecttip);
            guest->Response(res, this);
        }
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        connectmap.erase(this);
    }
    return;
reconnect:
    if (connect() < 0) {
        destory();
    }
}

void Host::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("host error: %s\n", strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }
    
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean(PEER_LOST_ERR, this);
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
            guest->writedcb(this);
    }
}

void Host::Dnscallback(Host* host, const Dns_rcd&& rcd) {
    connectmap[host]=time(NULL);
    if (rcd.result != 0) {
        LOGE("Dns query failed: %s\n", host->hostname);
    } else {
        host->addrs = rcd.addrs;
        for (size_t i = 0; i < host->addrs.size(); ++i) {
            host->addrs[i].addr_in6.sin6_port = htons(host->port);
        }
        host->connect();
    }
}

int Host::connect(){
    connectmap[this]=time(NULL);
    if(udp_mode){
        return connect_udp();
    }else{
        return connect_tcp();
    }
}

int Host::connect_tcp() {
    if (testedaddr>= addrs.size()) {
        return -1;
    } else {
        if (fd > 0) {
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++], SOCK_STREAM);
        if (fd < 0) {
            LOGE("connect to %s failed\n", this->hostname);
            return connect();
        }
        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        return 0;
    }
}


int Host::connect_udp(){
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == nullptr) {
        return -1;
    }
    if (testedaddr>= addrs.size()) {
        return -1;
    } else {
        if (fd > 0) {
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++], SOCK_DGRAM);
        if (fd < 0) {
            LOGE("connect to %s failed\n", this->hostname);
            return connect();
        }
        HttpResHeader res(connecttip);
        guest->Response(res, this);

        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT | EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
        return 0;
    }

}

void Host::destory() {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if(guest){
        HttpResHeader res(H500);
        guest->Response(res, this);
    }
    clean(CONNECT_ERR, this);
    delete this;
}


Host::~Host(){
    connectmap.erase(this);
}


void Host::Request(Guest* guest, HttpReqHeader& req) {
    size_t len;
    char *buff = req.getstring(len);
    Write(buff, len, this);
    if(req.ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY;
    }
    this->req = req;
}

void Host::ResProc(HttpResHeader& res) {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }
    guest->Response(res, this);
}



Host* Host::gethost(HttpReqHeader &req, Guest* guest) {
#ifdef CLIENT
    if (checkproxy(req.hostname)) {
        return Proxy::getproxy(req, guest);
    }
#endif
    Host* exist = dynamic_cast<Host *>(queryconnect(guest));
    if (exist && strcasecmp(exist->hostname, req.hostname) == 0
        && exist->port == req.port
        && !req.ismethod("SEND"))
    {
        exist->Request(guest, req);
        return exist;
    }

    if (exist) { 
        exist->clean(NOERROR, guest);
    }
    return new Host(req, guest);
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
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean(PEER_LOST_ERR, this);
        return -1;
    }

    int len = guest->bufleft(this);

    if (len <= 0) {
        LOGE("The guest's write buff is full\n");
        guest->wait(this);
        return -1;
    }

    return guest->Write(buff, Min(size, len), this);
}

void hosttick() {
    for(auto i = connectmap.begin();i != connectmap.end();){
        Host *host = (Host *)(i->first);
        if(time(NULL) - i->second >= 30 && host->connect() < 0){
            connectmap.erase(i++);
            LOGE("connect to %s time out.\n", host->hostname);
            host->destory();
        }else{
            i++;
        }
    }
}

