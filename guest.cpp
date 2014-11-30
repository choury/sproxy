#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>

#include "guest.h"
#include "proxy.h"
#include "parse.h"



Guest::Guest(int fd): Peer(fd) {
    struct sockaddr_in6 sa;
    socklen_t len = sizeof(sa);

    if (getpeername(fd, (struct sockaddr*)&sa, &len)) {
        perror("getpeername");
        strcpy(sourceip, "Unknown IP");
    } else {
        inet_ntop(AF_INET6, &sa.sin6_addr, sourceip, sizeof(sourceip));
        sourceport = ntohs(sa.sin6_port);
    }

    struct sockaddr_in  Dst;
    socklen_t sin_size = sizeof(Dst);
    struct sockaddr_in6 Dst6;
    socklen_t sin6_size = sizeof(Dst6);

    int socktype;

    if ((getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &Dst, &sin_size) || (socktype = AF_INET, 0)) &&
            (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &Dst6, &sin6_size) || (socktype = AF_INET6, 0))) {
        LOGE( "([%s]:%d): getsockopt error:%s\n",
              sourceip, sourceport, strerror(errno));
        strcpy(destip, "Unkown IP");
        destport = CPORT;
    } else {
        switch(socktype) {
        case AF_INET:
            inet_ntop(socktype, &Dst.sin_addr, destip, INET6_ADDRSTRLEN);
            destport = ntohs(Dst.sin_port);
            break;

        case AF_INET6:
            inet_ntop(socktype, &Dst6.sin6_addr, destip, INET6_ADDRSTRLEN);
            destport = ntohs(Dst6.sin6_port);
            break;
        }
    }
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    handleEvent=(void (Con::*)(uint32_t))&Guest::getheaderHE;
}

Guest::Guest() {

}


void Guest::connected(const char *method) {
    if(strcasecmp(method,"CONNECT")==0){
        Write(this,connecttip, strlen(connecttip));
    }
    if(readlen){
        Host *host=(Host *)bindex.query(this);
        if(host == NULL) {
            LOGE("([%s]:%d): connecting to host lost\n",sourceip, sourceport);
            clean(this);
            return;
        }
        host->Write(this,rbuff, readlen);
        readlen = 0;
    }
    
    if(expectlen){
        handleEvent=(void (Con::*)(uint32_t))&Guest::postHE;
    }
    
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

int Guest::showerrinfo(int ret,const char *s) {
    if(ret<0) {
        LOGE("([%s]:%d):%s:%s\n",
             sourceip, sourceport,s,strerror(errno));
    }
    return 1;
}


void Guest::getheaderHE(uint32_t events) {
    if (events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            clean(this);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"guest read error")) {
                clean(this);
            }
            return;
        }

        readlen += ret;

        if (uchar* headerend = (uchar *)strnstr((char *)rbuff, CRLF CRLF, readlen)) {
            headerend += strlen(CRLF CRLF);
            size_t headerlen = headerend - rbuff;
            try {
                HttpReqHeader *Req=new HttpReqHeader(rbuff);
                if (headerlen != readlen) {       //除了头部还读取到了其他内容
                    readlen -= headerlen;
                    memmove(rbuff, headerend, readlen);
                } else {
                    readlen = 0;
                }

                if(checkproxy(Req->hostname)){
                    LOG( "([%s]:%d): PROXY %s %s\n",
                         sourceip, sourceport,
                         Req->method, Req->url);
                }else{
                    LOG( "([%s]:%d): %s %s\n",
                        sourceip, sourceport,
                        Req->method, Req->url);
                }

    
                if ( Req->ismethod("GET") ||  Req->ismethod("HEAD") ) {
                    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                    Host::gethost(Req,this);
                } else if (Req->ismethod("POST") ) {
                    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                    const char* lenpoint=Req->getval("Content-Length");
                    if (lenpoint == NULL) {
                        LOGE( "([%s]:%d): unsported post version\n",sourceip, sourceport);
                        clean(this);
                        return;
                    }
                    sscanf(lenpoint, "%u", &expectlen);
                    expectlen-=readlen;
                    Host::gethost(Req,this);
                } else if (Req->ismethod("CONNECT")) {
                    epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                    Host::gethost(Req,this);
                    handleEvent=(void (Con::*)(uint32_t))&Guest::defaultHE;
                }else if (Req->ismethod("ADDPSITE")) {
                    addpsite(Req->url);
                    Write(this,ADDBTIP, strlen(ADDBTIP));
                    delete Req;
                } else if(Req->ismethod("DELPSITE")) {
                    if(delpsite(Req->url)) {
                        Write(this,DELBTIP,strlen(DELBTIP));
                    } else {
                        Write(this,DELFTIP,strlen(DELFTIP));
                    }
                    delete Req;
                } else if(Req->ismethod("GLOBALPROXY")) {
                    if(globalproxy()) {
                        Write(this,EGLOBLETIP, strlen(EGLOBLETIP));
                    } else {
                        Write(this,DGLOBLETIP, strlen(DGLOBLETIP));
                    }
                    delete Req;
                } else {
                    LOGE( "([%s]:%d): unsported method:%s\n",
                          sourceip, sourceport,Req->method);
                    clean(this);
                    delete Req;
                }
            } catch(...) {
                clean(this);
                return;
            }

        }
    }
    defaultHE(events&(~EPOLLIN));
}


void Guest::postHE(uint32_t events) {
    if (events & EPOLLIN) {
        char buff[1024 * 1024];
        Host *host=(Host *)bindex.query(this);
        if(host == NULL) {
            LOGE("([%s]:%d): connecting to host lost\n",sourceip, sourceport);
            clean(this);
            return;
        }
        int len=host->bufleft();
        if(len == 0) {
            LOGE( "([%s]:%d): The host's buff is full\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(buff, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"guest read error")) {
                clean(this);
            }
            return;
        }
        expectlen -= ret;
        host->Write(this,buff, ret);
        if (expectlen == 0) {
            handleEvent=(void (Con::*)(uint32_t))&Guest::getheaderHE;
        }

    }
    defaultHE(events&(~EPOLLIN));
}


void Guest::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    
    Host *host=(Host *)bindex.query(this);
    if (events & EPOLLIN) {
        char buff[1024 * 1024];
        if(host == NULL) {
            LOGE("([%s]:%d): connecting to host lost\n",sourceip, sourceport);
            clean(this);
            return;
        }
        int len=host->bufleft();
        if(len == 0) {
            LOGE( "([%s]:%d): The host's buff is full\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(buff, len);
        if(ret <= 0 ) {
            if(showerrinfo(ret,"guest read error")) {
                clean(this);
            }
            return;
        }
        host->Write(this,buff, ret);
    }
    if (events & EPOLLOUT) {
        if(writelen) {
            int ret = Write();
            if (ret <= 0 ) {
                if( showerrinfo(ret,"guest write error")) {
                    clean(this);
                }
                return;
            }
            if (host)
                host->writedcb();
        }

        if(writelen==0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE( "([%s]:%d): guest error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
    }
}

void Guest::closeHE(uint32_t events) {
    if (events & EPOLLOUT) {
        if(writelen == 0) {
            delete this;
            return;
        }

        int ret = Write();

        if (ret <= 0 && showerrinfo(ret,"write error while closing")) {
            delete this;
            return;
        }
    }
}


void Guest::clean(Peer *) {
    Host *host =(Host *)bindex.query(this);
    if(host) {
        host->clean(this);
    }
    bindex.del(this,host);

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent=(void (Con::*)(uint32_t))&Guest::closeHE;
}


