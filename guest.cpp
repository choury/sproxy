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
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled now" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF
#define SWITCHTIP   "HTTP/1.0 200 Switched proxy server" CRLF CRLF

#define BLOCKTIP    "HTTP/1.1 403 Forbidden" CRLF \
                    "Content-Length:73" CRLF CRLF \
                    "This site is blocked, please contact administrator for more information" CRLF

#define DELFTIP    "HTTP/1.0 404 The site is not found" CRLF CRLF

#define AUTHNEED    "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF \
                    "Content-Length: 0" CRLF CRLF
                    
#define PROXYTIP    "HTTP/1.1 200 Proxy" CRLF \
                    "Content-Length:48" CRLF CRLF \
                    "This site is proxyed, you can do what you want" CRLF
                    
#define NORMALIP    "HTTP/1.1 200 Ok" CRLF \
                    "Content-Length:56" CRLF CRLF \
                    "This site won't be proxyed, you can add it by addpsite" CRLF

char SHOST[DOMAINLIMIT];
uint16_t SPORT = 443;
char *auth_string=nullptr;

std::set<Guest *> guest_set;

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
        int ret = Peer::Write();
        if (ret <= 0) {
            if (showerrinfo(ret, "guest write error")) {
                clean(WRITE_ERR, this);
            }
            return;
        }
        Peer *host;
        if (ret != WRITE_NOTHING && (host = queryconnect(this)))
            host->writedcb(this);

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
    this->flag = 0;
    if (auth_string &&
        !checkauth(sourceip) &&
        req.get("Proxy-Authorization") &&
        strcmp(auth_string, req.get("Proxy-Authorization")+6) == 0)
    {
        addauth(sourceip);
    }
    if (req.ismethod("GET") || 
        req.ismethod("POST") || 
        req.ismethod("PUT") || 
        req.ismethod("PATCH") || 
        req.ismethod("CONNECT") || 
        req.ismethod("HEAD") || 
        req.ismethod("SEND")) 
    {
        if (auth_string && !checkauth(sourceip)){
            Peer::Write(AUTHNEED, strlen(AUTHNEED), this);
        }else if (checkblock(req.hostname) || checklocal(req.hostname)) {
            LOG("([%s]:%d): site: %s blocked\n",
                 sourceip, sourceport, req.hostname);
            Peer::Write(BLOCKTIP, strlen(BLOCKTIP), this);
        } else {
            Host::gethost(req, this);
        }
#ifdef CLIENT
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
        flushproxy2();
        Peer::Write(SWITCHTIP, strlen(SWITCHTIP));
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
#endif
/*    } else if (req.ismethod("SHOW")){
        writelen += ::showstatus(wbuff+writelen, req.url);
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);*/
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            Peer::Write(H200, strlen(H200));
            return;
        }
    } else{
        LOGE("([%s]:%d): unsported method:%s\n",
              sourceip, sourceport, req.method);
        clean(HTTP_PROTOCOL_ERR, this);
    }
}

void Guest::Response(HttpResHeader& res, Peer*) {
    size_t len;
    char *buff=res.getstring(len);
    Peer::Write(buff, len, this);
    if(res.get("Transfer-Encoding")){
        flag |= ISCHUNKED_F;
    }
}

ssize_t Guest::Write(void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    ssize_t ret = 0;
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        if(Peer::Write((const void *)chunkbuf, chunklen, this) != chunklen)
            assert(0);
        ret = Peer::Write(buff, len, this);
        if(Peer::Write(CRLF, strlen(CRLF), this) != strlen(CRLF))
            assert(0);
    }else{
        ret = Peer::Write(buff, size, this);
    }
    return ret;
}

ssize_t Guest::Write(const void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    ssize_t ret = 0;
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        if(Peer::Write((const void *)chunkbuf, chunklen, this) != chunklen)
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
