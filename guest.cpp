#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>

#include "guest.h"
#include "proxy.h"
#include "parse.h"



Guest::Guest(int fd, int efd): Peer(fd, efd) {
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


void Guest::connected() {
    Write(connecttip, strlen(connecttip));
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
        int len=sizeof(rbuff)-read_len;
        if(len<0) {
            LOGE("([%s]:%d):connecting to host lost\n",sourceip, sourceport);
            clean();
            return;
        } else if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+read_len, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"guest read error")) {
                clean();
            }
            return;
        }

        read_len += ret;

        if (char* headerend = strnstr(rbuff, CRLF CRLF, read_len)) {
            headerend += strlen(CRLF CRLF);
            size_t headerlen = headerend - rbuff;
            char buff[4096];
            try {
                Http http(rbuff);
                if (headerlen != read_len) {       //除了头部还读取到了其他内容
                    read_len -= headerlen;
                    memmove(rbuff, headerend, read_len);
                } else {
                    read_len = 0;
                }
                bool shouldproxy=false;
                if (destport == CPORT) {
                    if(http.checkproxy()) {
                        host = Proxy::getproxy(host, efd, this);
                        host->Write(buff, http.getstring(buff,true));
                        host->Write(rbuff, read_len);
                        read_len = 0;
                        LOG( "([%s]:%d): PROXY %s %s\n",
                             sourceip, sourceport,
                             http.method, http.url);
                        handleEvent=(void (Con::*)(uint32_t))&Guest::defaultHE;
                        return;
                    }
                } else if(destport == HTTPPORT) {
                    strcpy(http.hostname, http.getval("Host").c_str());
                    strcpy(http.path, http.url);
                    sprintf(http.url, "http://%s%s", http.hostname , http.path);
                    http.port = HTTPPORT;
                    shouldproxy=true;
                } else {
                    LOGE("Unkown Port\n");
                    clean();
                    return;
                }

                LOG( "([%s]:%d): %s %s\n",
                     sourceip, sourceport,
                     http.method, http.url);

                if ( http.ismethod("GET") ||  http.ismethod("HEAD") ) {
                    if(shouldproxy) {
                        host = Proxy::getproxy(host,efd,this);
                    } else {
                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                    }
                    host->Write(buff, http.getstring(buff,shouldproxy));
                } else if (http.ismethod("POST") ) {
                    int writelen=http.getstring(buff,shouldproxy);
                    char* lenpoint;
                    if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                        LOGE( "([%s]:%d): unsported post version\n",sourceip, sourceport);
                        clean();
                        return;
                    }

                    sscanf(lenpoint + 15, "%u", &expectlen);
                    expectlen -= read_len;

                    if(shouldproxy) {
                        host=Proxy::getproxy(host,efd,this);
                    } else {
                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                    }
                    host->Write(buff, writelen);
                    host->Write(rbuff, read_len);
                    read_len = 0;
                    handleEvent=(void (Con::*)(uint32_t))&Guest::postHE;
                } else if (http.ismethod("CONNECT")) {
                    if(shouldproxy) {
                        host=Proxy::getproxy(host,efd,this);
                    } else {
                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                    }
                    handleEvent=(void (Con::*)(uint32_t))&Guest::defaultHE;
                    connectedcb=&Guest::connected;
                } else if (http.ismethod("LOADPLIST")) {
                    if (loadproxysite() > 0) {
                        Write(LOADBSUC, strlen(LOADBSUC));
                    } else {
                        Write(H404, strlen(H404));
                    }
                } else if (http.ismethod("ADDPSITE")) {
                    addpsite(http.url);
                    Write(ADDBTIP, strlen(ADDBTIP));
                } else if(http.ismethod("DELPSITE")) {
                    if(delpsite(http.url)) {
                        Write(DELBTIP,strlen(DELBTIP));
                    } else {
                        Write(H404,strlen(H404));
                    }
                } else if(http.ismethod("GLOBALPROXY")) {
                    if(globalproxy()) {
                        Write(EGLOBLETIP, strlen(EGLOBLETIP));
                    } else {
                        Write(DGLOBLETIP, strlen(DGLOBLETIP));
                    }
                } else {
                    LOGE( "([%s]:%d): unsported method:%s\n",
                          sourceip, sourceport,http.method);
                    clean();
                }
            } catch(...) {
                clean();
                return;
            }

        }
    }
    defaultHE(events&(~EPOLLIN));
}


void Guest::postHE(uint32_t events) {
    if (events & EPOLLIN) {
        char buff[1024 * 1024];
        if(host == NULL) {
            LOGE("([%s]:%d):connecting to host lost\n",sourceip, sourceport);
            clean();
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
                clean();
            }
            return;
        }
        expectlen -= ret;
        host->Write(buff, ret);
        if (expectlen == 0) {
            handleEvent=(void (Con::*)(uint32_t))&Guest::getheaderHE;
        }

    }
    defaultHE(events&(~EPOLLIN));
}


void Guest::closeHE(uint32_t events) {
    if (events & EPOLLOUT) {
        if(write_len == 0) {
            delete this;
            return;
        }

        int ret = Write();

        if (ret <= 0 && showerrinfo(ret,"guest write error")) {
            delete this;
            return;
        }
    }
}


void Guest::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    if (events & EPOLLIN) {
        char buff[1024 * 1024];
        if(host == NULL) {
            LOGE("([%s]:%d):connecting to host lost\n",sourceip, sourceport);
            clean();
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
                clean();
            }
            return;
        }
        host->Write(buff, ret);
    }
    if (events & EPOLLOUT) {
        if(write_len) {
            int ret = Write();
            if (ret <= 0 ) {
                if( showerrinfo(ret,"guest write error")) {
                    clean();
                }
                return;
            }
            if (host)
                host->writedcb();
        }

        if(write_len==0) {
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
        clean();
    }
}


void Guest::clean() {
    if(host) {
        host->guest=NULL;
    }
    host=NULL;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    handleEvent=(void (Con::*)(uint32_t))&Guest::closeHE;
}
