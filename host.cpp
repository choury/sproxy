#include "host.h"
#include "proxy.h"


#define DNSERRTIP   "HTTP/1.0 502 Bad Gateway" CRLF CRLF\
                    "Dns Query failed, you can try angin"
                    
#define CONERRTIP   "HTTP/1.0 504 Gateway Timeout" CRLF CRLF\
                    "Connect to the site failed, you can try angin"

Host::Host(HttpReqHeader& req, Guest* guest, Http::Initstate state):Peer(0), Http(state), req(req) {
    ::connect(guest, this);
    writelen = req.getstring(wbuff);
    this->req = req;
    snprintf(hostname, sizeof(hostname), "%s", req.hostname);
    port = req.port;
    if (query(hostname, (DNSCBfunc)Host::Dnscallback, this) < 0) {
        LOGE("DNS qerry falied\n");
        throw 0;
    }
}


Host::Host(HttpReqHeader &req, Guest* guest, const char* hostname, uint16_t port):Peer(0), Http(ALWAYS), req(req) {
    ::connect(guest, this);
    writelen = req.getstring(wbuff);
    this->req = req;
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);
    this->port = port;

    if (query(hostname, (DNSCBfunc)Host::Dnscallback, this) < 0) {
        LOGE("DNS qerry falied\n");
        throw 0;
    }
}


int Host::showerrinfo(int ret, const char* s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("%s: %s\n", s, strerror(errno));
        } else {
            return 0;
        }
    }
    return 1;
}


void Host::waitconnectHE(uint32_t events) {
    connectset.del(this);
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == nullptr) {
        clean();
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
            res.id = req.id;
            guest->Response(res);
        }
        handleEvent = (void (Con::*)(uint32_t))&Host::defaultHE;
    }
    return;
reconnect:
    if (connect() < 0) {
        destory(CONERRTIP);
    }
}

void Host::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("host error: %s\n", strerror(error));
        }
        clean();
        return;
    }
    
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean();
        return;
    }

    if (events & EPOLLIN) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "host write error")) {
                    clean();
                }
                return;
            }
            guest->writedcb();
        }
    }

    if (writelen == 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}


void Host::closeHE(uint32_t events) {
    connectset.del(this);
    delete this;
}



void Host::Dnscallback(Host* host, const Dns_rcd&& rcd) {
    if (rcd.result != 0) {
        LOGE("Dns query failed\n");
        host->destory(DNSERRTIP);
    } else {
        host->addrs = rcd.addrs;
        for (size_t i = 0; i < host->addrs.size(); ++i) {
            host->addrs[i].addr_in6.sin6_port = htons(host->port);
        }
        if (host->connect() < 0) {
            LOGE("connect to %s failed\n", host->hostname);
            host->destory(CONERRTIP);
        }
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
        connectset.add(this);
        return 0;
    }
}


void Host::destory(const char* tip) {
    Peer *guest = queryconnect(this);
    if(guest){
        disconnect(this);
        if(tip)
            guest->Write(this,tip,strlen(tip));
    }
    connectset.del(this);
    delete this;
}


void Host::Request(HttpReqHeader &req, Guest *guest) {
    writelen+= req.getstring(wbuff+writelen);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    this->req = req;
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
        exist->Request(req, guest);
        return exist;
    }

    if (exist != NULL) {
        exist->clean();
    }

    return new Host(req, guest);
}


ssize_t Host::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}

void Host::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Host read")) {
        clean();
    }
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean();
        return -1;
    }

    int len = guest->bufleft();

    if (len == 0) {
        LOGE("The guest's write buff is full\n");
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
        return -1;
    }

    return guest->Write(this, buff, Min(size, len));
}


ConnectSet connectset;

void ConnectSet::add(Peer* key) {
    map[key]=time(NULL);
}

void ConnectSet::del(Peer* key) {
    map.erase(key);
}

void ConnectSet::tick() {
    for(auto i = map.begin();i != map.end();){
        Host *host = (Host *)(i->first);
        if(host && time(NULL) - i->second >= 30 && host->connect() < 0){
            map.erase(i++);
            LOGE("connect to %s time out.", host->hostname);
            host->destory(CONERRTIP);
        }else{
            i++;
        }
    }
}

