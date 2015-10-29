#ifdef CLIENT
#include "proxy.h"
#else
#include "host.h"
#endif

#include <map>
#include <string.h>
                    
std::map<Host*,time_t> connectmap;

Host::Host(HttpReqHeader& req, Guest* guest):Peer(0), req(req) {
    ::connect(guest, this);
    Request(guest, req, false);
    snprintf(hostname, sizeof(hostname), "%s", req.hostname);
    port = req.port;
    if(req.ismethod("CONNECT")){
        Http_Proc = &Host::AlwaysProc;
    }
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
}


Host::Host(HttpReqHeader &req, Guest* guest, const char* hostname, uint16_t port):Peer(0), req(req) {
    ::connect(guest, this);
    Request(guest, req, false);
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);
    this->port = port;
    if(req.ismethod("CONNECT")){
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
    connectmap.erase(this);
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
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "host write error")) {
                    clean(WRITE_ERR, this);
                }
                return;
            }
            guest->writedcb(this);
        }
        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


void Host::closeHE(uint32_t events) {
    connectmap.erase(this);
    delete this;
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

int Host::connect() {
    if (testedaddr>= addrs.size()) {
        return -1;
    } else {
        if (fd > 0) {
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++].addr);
        if (fd < 0) {
            LOGE("connect to %s failed\n", this->hostname);
            return connect();
        }
        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        handleEvent = (void (Con::*)(uint32_t))&Host::waitconnectHE;
        connectmap[this]=time(NULL);
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
    connectmap.erase(this);
    delete this;
}


void Host::Request(Guest* guest, HttpReqHeader& req, bool direct_send) {
    writelen+= req.getstring(wbuff+writelen);
    if(direct_send){
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    guest->flag = 0;
    if(req.ismethod("HEAD")){
        ignore_body = true;
    }else if(req.ismethod("CONNECT")){
        guest->flag = ISCONNECT_F;
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
    if (exist && exist->port == req.port
        && strcasecmp(exist->hostname, req.hostname) == 0)
    {
        exist->Request(guest, req, true);
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

int Host::showstatus(char* buff, Peer*) {
    int len;
    len = sprintf(buff, "%s ", req.url);
    const char *status;
    if(handleEvent ==  nullptr)
        status = "Waiting dns";
    else if(handleEvent == (void (Con::*)(uint32_t))&Host::waitconnectHE)
        status = "connecting...";
    else if(handleEvent == (void (Con::*)(uint32_t))&Host::defaultHE)
        status = "transfer data";
    else if(handleEvent == (void (Con::*)(uint32_t))&Host::closeHE)
        status = "Waiting close";
    else
        status = "unkown status";
    
    len += sprintf(buff+len, "##%s\r\n", status);
    return len;
}


void hosttick() {
    for(auto i = connectmap.begin();i != connectmap.end();){
        Host *host = (Host *)(i->first);
        if(host && time(NULL) - i->second >= 30 && host->connect() < 0){
            connectmap.erase(i++);
            LOGE("connect to %s time out.\n", host->hostname);
            host->destory();
        }else{
            i++;
        }
    }
}

