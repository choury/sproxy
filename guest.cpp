#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/epoll.h>
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
        perror("getsockopt error");
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
    peerlist.push_back(this);

}


void Guest::connected() {
    if (status == connect_s) {
        Write(connecttip, strlen(connecttip));
    }
}

bool Guest::candelete() {
    return status == close_s && write_len == 0;
}



void Guest::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    int ret;
    unsigned int len;

    if (events & EPOLLIN) {
        char buff[1024 * 1024];

        switch (status) {
        case start_s:
            if (read_len == 4096) {
                fprintf(stderr, "([%s]:%d): too large header\n",
                        sourceip, sourceport);
                clean();
                break;
            }

            ret = Read(rbuff + read_len, 4096 - read_len);

            if (ret <= 0) {
                clean();
                break;
            }

            read_len += ret;

            if (char* headerend = strnstr(rbuff, CRLF CRLF, read_len)) {
                headerend += strlen(CRLF CRLF);
                size_t headerlen = headerend - rbuff;

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
                            status = proxy_s;
                            fprintf(stdout, "([%s]:%d): PROXY %s %s\n",
                                    sourceip, sourceport,
                                    http.method, http.url);
                            break;
                        }
                    } else if(destport == HTTPPORT) {
                        strcpy(http.hostname, http.getval("Host").c_str());
                        strcpy(http.path, http.url);
                        sprintf(http.url, "http://%s%s", http.hostname , http.path);
                        http.port = HTTPPORT;
                        shouldproxy=true;
                    } else {
                        fprintf(stderr,"Unkown Port\n");
                        clean();
                        return;
                    }

                    fprintf(stdout, "([%s]:%d): %s %s\n",
                            sourceip, sourceport,
                            http.method, http.url);


                    if ( http.ismethod("GET") ||  http.ismethod("HEAD") ) {
                        if(shouldproxy) {
                            host=Proxy::getproxy(host,efd,this);
                        } else {
                            host = Host::gethost(host, http.hostname, http.port, efd, this);
                        }
                        host->Write(buff, http.getstring(buff,shouldproxy));
                        status = start_s;
                    } else if (http.ismethod("POST") ) {
                        int writelen=http.getstring(buff,shouldproxy);
                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            fprintf(stderr, "([%s]:%d): unsported post version\n",
                                    sourceip, sourceport);
                            clean();
                            break;
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
                        status = post_s;

                    } else if (http.ismethod("CONNECT")) {
                        if(shouldproxy) {
                            host=Proxy::getproxy(host,efd,this);
                        } else {
                            host = Host::gethost(host, http.hostname, http.port, efd, this);
                        }
                        status = connect_s;

                    } else if (http.ismethod("LOADPLIST")) {
                        if (loadproxysite() > 0) {
                            Write(LOADBSUC, strlen(LOADBSUC));
                        } else {
                            Write(H404, strlen(H404));
                        }

                        status = start_s;
                    } else if (http.ismethod("ADDPSITE")) {
                        addpsite(http.url);
                        Write(ADDBTIP, strlen(ADDBTIP));
                        status = start_s;
                    } else if(http.ismethod("DELPSITE")) {
                        if(delpsite(http.url)) {
                            Write(DELBTIP,strlen(DELBTIP));
                        } else {
                            Write(H404,strlen(H404));
                        }
                        status = start_s;
                    } else if(http.ismethod("GLOBALPROXY")) {
                        if(globalproxy()) {
                            Write(EGLOBLETIP, strlen(EGLOBLETIP));
                        } else {
                            Write(DGLOBLETIP, strlen(DGLOBLETIP));
                        }
                        status = start_s;
                    } else {
                        fprintf(stderr, "([%s]:%d): unsported method:%s\n",
                                sourceip, sourceport,http.method);
                        clean();
                    }
                } catch(...) {
                    clean();
                    return;
                }

            }

            break;

        case post_s:
            len=host->bufleft();
            if(len==0) {
                fprintf(stderr, "([%s]:%d): The host's write buff is full\n",
                        sourceip, sourceport);
                epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                break;
            }
            ret = Read(buff , Min(len, expectlen));

            if (ret <= 0 ) {
                clean();
                break;
            }

            expectlen -= ret;
            host->Write(buff, ret);

            if (expectlen == 0) {
                status = start_s;
            }

            break;

        case connect_s:
        case proxy_s:
            len=host->bufleft();
            if(len==0) {
                fprintf(stderr, "([%s]:%d): The host's write buff is full\n",
                        sourceip, sourceport);
                epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                break;
            }

            ret = Read(buff, len);

            if (ret <= 0) {
                clean();
                break;
            }

            host->Write(buff, ret);
            break;

        default:
            break;
        }
    }

    if (events & EPOLLOUT) {
        int ret;
        switch (status) {
        case close_s:
            if(write_len == 0) {
                return;
            }

            ret = Write();

            if (ret < 0) {
                perror("guest write");
                clean();
                write_len = 0;
                return;
            }

            break;

        default:
            if(write_len) {
                ret = Write();
                if (ret <= 0) {
                    perror("guest write");
                    clean();
                    write_len = 0;
                    return;
                }

                if (fulled) {
                    if (host)
                        host->peercanwrite();

                    fulled = false;
                }
            }

            if (write_len == 0) {
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }
        }
    }


    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            fprintf(stderr, "([%s]:%d): guest error:%s\n",
                    sourceip, sourceport, strerror(error));
        }

        clean();
        write_len = 0;
    }

}


void Guest::clean() {
    status = close_s;
    pthread_mutex_lock(&lock);
    if(host) {
        host->guest=NULL;
        host->clean();
    }
    host=NULL;
    pthread_mutex_unlock(&lock);

    if (write_len) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}
