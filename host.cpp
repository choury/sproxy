#include "host.h"
#include "guest.h"

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


Host::Host(Host&& copy){
    fd = copy.fd;
    copy.fd  = 0;
}

Host::Host(const char* hostname, uint16_t port): port(port){
    memset(this->hostname, 0, sizeof(this->hostname));
    query(hostname, (DNSCBfunc)Host::Dnscallback, this);
    add_tick_func(hosttick, nullptr);
}

Ptr Host::shared_from_this() {
    return Peer::shared_from_this();
}

Host::~Host(){
    connectmap.erase(this);
}

void Host::Dnscallback(Host* host, const char *hostname, const Dns_rcd&& rcd) {
    snprintf(host->hostname, sizeof(host->hostname), "%s", hostname);
    if (rcd.addrs.size() == 0) {
        LOGE("Dns query failed: %s\n", host->hostname);
        host->clean(CONNECT_ERR, host);
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
            updateEpoll(0);
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++], SOCK_STREAM);
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
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if (guest == nullptr){
        clean(PEER_LOST_ERR, this);
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
            LOGE("getsokopt error: %m\n");
            goto reconnect;
        }
        if (error != 0) {
            LOGE("connect to %s: %s\n", this->hostname, strerror(error));
            goto reconnect;
        }
        updateEpoll(EPOLLIN | EPOLLOUT);

        if (http_flag & HTTP_CONNECT_F){
            HttpResHeader res(connecttip, shared_from_this());
            guest->response(res);
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
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if (guest == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("host error: %s\n", strerror(error));
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
            guest->writedcb(this);
    }
}


int Host::showerrinfo(int ret, const char* s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("%s: %m\n", s);
        } else {
            return 0;
        }
    }else if(ret){
        LOGE("%s:%d\n",s, ret);
    }
    return 1;
}



Ptr Host::request(HttpReqHeader& req) {
    size_t len;
    char *buff = req.getstring(len);
    Write(buff, len, this);
    if(req.ismethod("CONNECT")){
        http_flag = HTTP_CONNECT_F;
        Http_Proc = &Host::AlwaysProc;
    }else if(req.ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    guest_ptr = req.getsrc();
    return shared_from_this();
}

void Host::ResProc(HttpResHeader& res) {
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if (guest == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }
    guest->response(res);
}



Ptr Host::gethost(HttpReqHeader& req, Ptr responser_ptr) {
    Host* exist = dynamic_cast<Host *>(responser_ptr.get());
    if (exist && strcasecmp(exist->hostname, req.hostname) == 0
        && exist->port == req.port
        && !req.ismethod("CONNECT"))
    {
        return exist->request(req);
    }

    if (exist) { 
        exist->clean(NOERROR, nullptr);
    }
    return (new Host(req.hostname, req.port))->request(req);
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
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
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

void Host::clean(uint32_t errcode, Peer* who, uint32_t)
{
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if(guest){
        if(errcode == CONNECT_ERR){
            HttpResHeader res(H408, shared_from_this());
            guest->response(res);
        }
        if(who == this){
            guest->clean(errcode, this);
        }
    }
    if(hostname[0]){
        Peer::clean(errcode, who);
    }else{
        guest_ptr = nullptr;
    }
}


