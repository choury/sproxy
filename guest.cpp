#include "guest.h"
#include "host.h"

#include <set>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#define ADDPTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Block site Added" CRLF CRLF
#define DELPTIP    "HTTP/1.0 200 Proxy site Deleted" CRLF CRLF
#define DELBTIP    "HTTP/1.0 200 Block site Deleted" CRLF CRLF
#define DELFTIP    "HTTP/1.0 404 The site is not found" CRLF CRLF
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled now" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF
#define SWITCHTIP   "HTTP/1.0 200 Switched proxy server" CRLF CRLF

#define BLOCKTIP    "HTTP/1.1 403 Forbidden" CRLF \
                    "Content-Length:73" CRLF CRLF \
                    "This site is blocked, please contact administrator for more information" CRLF
                    
#define PROXYTIP    "HTTP/1.1 200 Proxy" CRLF \
                    "Content-Length:48" CRLF CRLF \
                    "This site is proxyed, you can do what you want" CRLF
                    
#define NORMALIP    "HTTP/1.1 200 Ok" CRLF \
                    "Content-Length:56" CRLF CRLF \
                    "This site won't be proxyed, you can add it by addpsite" CRLF

std::set<Guest *> guest_set;

int showstatus(char *buff, const char *command){
    if(command[0] == 0 || strcasecmp(command, "guest") == 0){
        int len = 0;
        len = sprintf(buff, "Guest:\r\n");
        for(auto i:guest_set){
            len += i->showstatus(buff+len, nullptr);
        }
        return len;
    }
    if(strcasecmp(command, "dns") == 0){
        return dnsstatus(buff);
    }
    return 0;
}
                    
Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Peer(fd) {
    guest_set.insert(this);
    inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
    sourceport = ntohs(myaddr->sin6_port);


    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest::defaultHE;
}

Guest::Guest(const Guest *const copy): Peer(copy->fd), sourceport(copy->sourceport){
    guest_set.insert(this);
    strcpy(this->sourceip, copy->sourceip);

}



int Guest::showerrinfo(int ret, const char *s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("([%s]:%d): %s:%s\n",
                 sourceip, sourceport, s, strerror(errno));
        } else {
            return 0;
        }
    }else if(ret){
        LOGE("([%s]:%d): %s:%d\n",sourceip, sourceport, s, ret);
    }
    return 1;
}

void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }
    
    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Peer::Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "guest write error")) {
                    clean(WRITE_ERR, this);
                }
                return;
            }
            if (Peer *peer = queryconnect(this))
                peer->writedcb(this);
        }

        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}

void Guest::closeHE(uint32_t events) {
    if (writelen == 0) {
        delete this;
        return;
    }

    int ret = Peer::Write();
    if (ret <= 0 && showerrinfo(ret, "write error while closing")) {
        delete this;
        return;
    }
}


ssize_t Guest::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}

void Guest::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Guest-Http error")) {
        clean(errcode, this);
    }
}

void Guest::ReqProc(HttpReqHeader& req) {
    const char *hint = "";
    if (checkproxy(req.hostname)) {
        hint = "PROXY ";
    }
    if(req.url[0] == '/'){
        LOG("([%s]:%d): %s%s %s%s\n", sourceip, sourceport,
            hint, req.method, req.hostname, req.url);
        if(!req.hostname[0]){
            Write(BLOCKTIP, strlen(BLOCKTIP), this);
            return;
        }
    }else{
        LOG("([%s]:%d): %s%s %s\n", sourceip, sourceport,
            hint, req.method, req.url);
    }
    flag = 0;
    if (req.ismethod("GET") || 
        req.ismethod("POST") || 
        req.ismethod("PATCH") || 
        req.ismethod("CONNECT") || 
        req.ismethod("HEAD")) 
    {
        if (checkblock(req.hostname)) {
            LOG("([%s]:%d): site: %s blocked\n",
                 sourceip, sourceport, req.hostname);
            Peer::Write(BLOCKTIP, strlen(BLOCKTIP), this);
        } else {
            Host::gethost(req, this);
        }
    } else if (req.ismethod("ADDPSITE")) {
        addpsite(req.url);
        Peer::Write(ADDPTIP, strlen(ADDPTIP));
    } else if (req.ismethod("DELPSITE")) {
        if (delpsite(req.url)) {
            Peer::Write(DELPTIP, strlen(DELPTIP));
        } else {
            Peer::Write(DELFTIP, strlen(DELFTIP));
        }
    } else if (req.ismethod("ADDBSITE")) {
        addbsite(req.url);
        Peer::Write(ADDBTIP, strlen(ADDBTIP));
    } else if (req.ismethod("DELBSITE")) {
        if (delbsite(req.url)) {
            Peer::Write(DELBTIP, strlen(DELBTIP));
        } else {
            Peer::Write(DELFTIP, strlen(DELFTIP));
        }
    } else if (req.ismethod("GLOBALPROXY")) {
        if (globalproxy()) {
            Peer::Write(EGLOBLETIP, strlen(EGLOBLETIP));
        } else {
            Peer::Write(DGLOBLETIP, strlen(DGLOBLETIP));
        }
    } else if (req.ismethod("SWITCH")) {
        SPORT = 443;
        spliturl(req.url, SHOST, nullptr, &SPORT);
        Peer::Write(SWITCHTIP, strlen(SWITCHTIP));
    } else if (req.ismethod("SHOW")){
        writelen += ::showstatus(wbuff+writelen, req.url);
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            Peer::Write(H200, strlen(H200));
            return;
        }
    } else if (req.ismethod("TEST")){
        if(checkblock(req.hostname)){
            Peer::Write(BLOCKTIP, strlen(BLOCKTIP));
            return;
        }
        if(checkproxy(req.hostname)){
            Peer::Write(PROXYTIP, strlen(PROXYTIP));
            return; 
        }
        Peer::Write(NORMALIP, strlen(NORMALIP));
    } else{
        LOGE("([%s]:%d): unsported method:%s\n",
              sourceip, sourceport, req.method);
        clean(HTTP_PROTOCOL_ERR, this);
    }
}

void Guest::Response(HttpResHeader& res, Peer*) {
    writelen+=res.getstring(wbuff+writelen);
    if(res.get("Transfer-Encoding")){
        flag |= ISCHUNKED_F;
    }
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}

ssize_t Guest::Write(const void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    ssize_t ret = 0;
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        if(Peer::Write(chunkbuf, chunklen, this) != chunklen)
            assert(0);
        ret = Peer::Write(buff, len, this);
        if(Peer::Write(CRLF, strlen(CRLF), this) != strlen(CRLF))
            assert(0);
    }else{
        ret = Peer::Write(buff, size, this);
    }
    return ret;
}


ssize_t Guest::DataProc(const void *buff, size_t size) {
    Host *host = dynamic_cast<Host *>(queryconnect(this));
    if (host == NULL) {
        LOGE("([%s]:%d): connecting to host lost\n", sourceip, sourceport);
        clean(PEER_LOST_ERR, this);
        return -1;
    }
    int len = host->bufleft(this);
    if (len <= 0) {
        LOGE("([%s]:%d): The host's buff is full\n", sourceip, sourceport);
        host->wait(this);
        return -1;
    }
    return host->Write(buff, Min(size, len), this);
}

Guest::~Guest(){
    guest_set.erase(this);
}

int Guest::showstatus(char* buff, Peer *){
    int len;
    len = sprintf(buff, "([%s]:%d) buffleft(%d): ", sourceip, sourceport,
                   (int32_t)(sizeof(wbuff)-writelen));
    Peer *peer = queryconnect(this);
    if(peer){
        len += peer->showstatus(buff+len, this);
    } else {
        len += sprintf(buff+len, "null ");
        const char *status;
        if(handleEvent ==  nullptr)
            status = "creating object";
        else if(handleEvent == (void (Con::*)(uint32_t))&Guest::defaultHE)
            status = "transfer data";
        else if(handleEvent == (void (Con::*)(uint32_t))&Guest::closeHE)
            status = "Waiting close";
        else
            status = "unkown status";
        len += sprintf(buff+len, "##%s\r\n", status);
    
    }
    return len;
}

