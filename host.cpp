#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "host.h"
#include "guest.h"
#include "parse.h"
#include "dns.h"
#include "proxy.h"



Host::Host() {

}

Host::Host(Guest* guest ,const char* hostname,uint16_t port) {
    bindex.add(guest,this);
    this->fd=0;
    write_len = 0;

    strcpy(this->hostname, hostname);
    this->targetport=port;


    handleEvent=(void (Con::*)(uint32_t))&Host::waitconnectHE;

    if(query(hostname,(DNSCBfunc)Host::Dnscallback,this)<0) {
        LOGE("DNS qerry falied\n");
        throw 0;
    }
}


int Host::showerrinfo(int ret, const char* s) {
    if (ret < 0) {
        LOGE("%s: %s\n",s,strerror(errno));
    }
    return 1;
}


void Host::waitconnectHE(uint32_t events) {
    Guest *guest=(Guest *)bindex.query(this);
    if( guest == NULL) {
        clean(this);
        return;
    }
    if (events & EPOLLOUT) {
        int error;
        socklen_t len=sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("getsokopt error: %s\n",strerror(error));
            clean(this);
            return;
        }
        if (error != 0) {
            LOGE( "connect to %s: %s\n",hostname, strerror(error));
            if(connect()<0) {
                clean(this);
            }
            return;
        }
        if(guest->connectedcb) {
            (guest->*guest->connectedcb)();
        }

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        handleEvent=(void (Con::*)(uint32_t))&Host::defaultHE;
    }
}


void Host::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    Guest *guest=(Guest *)bindex.query(this);
    if( guest == NULL) {
        clean(this);
        return;
    }

    if (events & EPOLLIN ) {
        int bufleft = guest->bufleft();

        if (bufleft == 0) {
            LOGE( "The guest's write buff is full\n");
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }

        char buff[1024 * 1024];
        int ret = Read(buff, bufleft);

        if (ret <= 0 ) {
            if(showerrinfo(ret,"host read error")) {
                clean(this);
                return;
            }
        } else {
            guest->Write(this,buff, ret);
        }

    }

    if (events & EPOLLOUT) {
        if (write_len) {
            int ret = Write();
            if (ret <= 0) {
                if(showerrinfo(ret,"host write error")) {
                    clean(this);
                }
                return;
            }
            guest->writedcb();

        }

        if (write_len == 0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }

    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("host unkown error: %s\n",strerror(errno));
        clean(this);
    }

}


void Host::closeHE(uint32_t events) {
    delete this;
}



void Host::Dnscallback(Host* host, const Dns_rcd&& rcd) {
    if(rcd.result!=0) {
        LOGE("Dns query failed\n");
        host->clean(host);
    } else {
        host->addr=rcd.addr;
        for(size_t i=0; i<host->addr.size(); ++i) {
            host->addr[i].addr_in6.sin6_port=htons(host->targetport);
        }
        if(host->connect()<0) {
            LOGE("connect to %s failed\n",host->hostname);
            host->clean(host);
        } else {
            epoll_event event;
            event.data.ptr=host;
            event.events=EPOLLOUT;
            epoll_ctl(efd,EPOLL_CTL_ADD,host->fd,&event);
        }
    }
}

int Host::connect() {
    if(testedaddr>= addr.size()) {
        return -1;
    } else {
        if(fd>0) {
            close(fd);
        }
        fd=Connect(&addr[testedaddr++].addr);
        if(fd <0 ) {
            LOGE("connect to %s failed\n",hostname);
            return connect();
        }
    }
    return 0;
}


void Host::clean(Peer *who) {
    Guest *guest =(Guest *)bindex.query(this);
    if(guest && who != guest) {
        guest->clean(this);
    }
    bindex.del(this,guest);

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    handleEvent=(void (Con::*)(uint32_t))&Host::closeHE;
}


Host* Host::gethost(HttpReqHeader* http,Guest* guest) {
    if(checkproxy(http->hostname)) {
        return Proxy::getproxy(guest,http);
    } else {
        Host* exist=(Host *)bindex.query(guest);
        char buff[HEALLENLIMIT];
        if (exist && exist->targetport == http->port && strcasecmp(exist->hostname, http->hostname) == 0) {
            exist->Write(guest,buff, http->getstring(buff));
            return exist;
        }
        if (exist != NULL) {
            exist->clean(guest);
        }
        Host *newhost = new Host(guest,http->hostname,http->port);
        newhost->Write(guest,buff, http->getstring(buff));
        return newhost;
    }
}

