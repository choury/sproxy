#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <limits.h>
#include <linux/netfilter_ipv4.h>

#include "guest.h"
#include "proxy.h"
#include "parse.h"


#define ADDPTIP    "HTTP/1.0 200 Proxy site Added" CRLF CRLF
#define ADDBTIP    "HTTP/1.0 200 Block site Added" CRLF CRLF
#define DELPTIP    "HTTP/1.0 200 Proxy site Deleted" CRLF CRLF
#define DELBTIP    "HTTP/1.0 200 Block site Deleted" CRLF CRLF
#define DELFTIP    "HTTP/1.0 404 The site is not found" CRLF CRLF
#define EGLOBLETIP  "HTTP/1.0 200 Global proxy enabled now" CRLF CRLF
#define DGLOBLETIP  "HTTP/1.0 200 Global proxy disabled" CRLF CRLF
#define SWITCHTIP   "HTTP/1.0 200 Switched proxy server" CRLF CRLF

#define BLOCKEDTIP  "HTTP/1.1 403 Forbidden" CRLF \
                    "Content-Length: 0" CRLF CRLF

#define AUTHORTIP   "HTTP/1.1 407 Proxy Authorization Required" CRLF \
                    "Proxy-Authenticate: Basic" CRLF \
                    "Content-Length: 0" CRLF CRLF


Guest::Guest(int fd): Peer(fd) {
    struct sockaddr_in6 sa;
    socklen_t len = sizeof(sa);

    if (getpeername(fd, (struct sockaddr*)&sa, &len)) {
        perror("getpeername");
        snprintf(sourceip, sizeof(sourceip), "%s", "Unknown IP");
    } else {
        inet_ntop(AF_INET6, &sa.sin6_addr, sourceip, sizeof(sourceip));
        sourceport = ntohs(sa.sin6_port);
    }

    struct sockaddr_in  Dst;
    socklen_t sin_size = sizeof(Dst);
    struct sockaddr_in6 Dst6;
    socklen_t sin6_size = sizeof(Dst6);

    int socktype;

    if ((getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &Dst, &sin_size)
            || (socktype = AF_INET, 0))
         && (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &Dst6, &sin6_size)
            || (socktype = AF_INET6, 0)))
    {
        LOGE("([%s]:%d): getsockopt error:%s\n",
              sourceip, sourceport, strerror(errno));
        snprintf(destip, sizeof(destip), "%s", "Unkown IP");
        destport = CPORT;
    } else {
        switch (socktype) {
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
    handleEvent = (void (Con::*)(uint32_t))&Guest::defaultHE;
}

Guest::Guest() {
}


int Guest::showerrinfo(int ret, const char *s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("([%s]:%d): %s:%s\n",
                 sourceip, sourceport, s, strerror(errno));
        } else {
            return 0;
        }
    }
    return 1;
}

void Guest::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    Peer *peer = bindex.query(this);
    if (events & EPOLLIN) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "guest write error")) {
                    clean(this);
                }
                return;
            }
            if (peer)
                peer->writedcb();
        }

        if (writelen == 0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
    }
}

void Guest::closeHE(uint32_t events) {
    if (writelen == 0) {
        delete this;
        return;
    }

    int ret = Write();

    if (ret <= 0 && showerrinfo(ret, "write error while closing")) {
        delete this;
        return;
    }
}


void Guest::ReqProc(HttpReqHeader& req) {
    if (checkproxy(req.hostname)) {
        LOG("([%s]:%d): PROXY %s %s\n",
             sourceip, sourceport,
             req.method, req.url);
    } else {
        LOG("([%s]:%d): %s %s\n",
             sourceip, sourceport,
             req.method, req.url);
    }

    if (req.ismethod("GET") || req.ismethod("POST") || req.ismethod("CONNECT")) {
        if (checkblock(req.hostname)) {
            LOG("([%s]:%d): site: %s blocked\n",
                 sourceip, sourceport, req.hostname);
            Write(this, BLOCKEDTIP, strlen(BLOCKEDTIP));
        } else {
            Host::gethost(req, this);
        }
    } else if (req.ismethod("ADDPSITE")) {
        addpsite(req.url);
        Write(this, ADDPTIP, strlen(ADDPTIP));
    } else if (req.ismethod("DELPSITE")) {
        if (delpsite(req.url)) {
            Write(this, DELPTIP, strlen(DELPTIP));
        } else {
            Write(this, DELFTIP, strlen(DELFTIP));
        }
    } else if (req.ismethod("ADDBSITE")) {
        addbsite(req.url);
        Write(this, ADDBTIP, strlen(ADDBTIP));
    } else if (req.ismethod("DELBSITE")) {
        if (delbsite(req.url)) {
            Write(this, DELBTIP, strlen(DELBTIP));
        } else {
            Write(this, DELFTIP, strlen(DELFTIP));
        }
    } else if (req.ismethod("GLOBALPROXY")) {
        if (globalproxy()) {
            Write(this, EGLOBLETIP, strlen(EGLOBLETIP));
        } else {
            Write(this, DGLOBLETIP, strlen(DGLOBLETIP));
        }
    } else if (req.ismethod("SWITCH")) {
        SPORT = 443;
        spliturl(req.url, SHOST, nullptr, &SPORT);
        Write(this, SWITCHTIP, strlen(SWITCHTIP));
    } else {
        LOGE("([%s]:%d): unsported method:%s\n",
              sourceip, sourceport, req.method);
        clean(this);
    }
}

void Guest::Response(HttpResHeader& res) {
    writelen+=res.getstring(wbuff+writelen);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}



ssize_t Guest::DataProc(const void *buff, size_t size) {
    Host *host = dynamic_cast<Host *>(bindex.query(this));
    if (host == NULL) {
        LOGE("([%s]:%d): connecting to host lost\n", sourceip, sourceport);
        clean(this);
        return -1;
    }
    int len = host->bufleft();
    if (len == 0) {
        LOGE("([%s]:%d): The host's buff is full\n", sourceip, sourceport);
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
        return -1;
    }
    return host->Write(this, buff, Min(size, len));
}
