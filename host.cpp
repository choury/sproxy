#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/epoll.h>

#include "host.h"
#include "guest.h"
#include "dns.h"



Host::Host(int efd, Guest* guest ,const char *hostname,uint16_t port): guest(guest) {

    this->efd = efd;
    this->fd=0;
    write_len = 0;

    strcpy(this->hostname, hostname);
    this->targetport=port;


    if(query(hostname,(DNSCBfunc)Host::Dnscallback,this)<0) {
        LOGE("DNS qerry falied\n");
        throw 0;
    }
    handleEvent=(void (Con::*)(uint32_t))&Host::waitconnectHE;
}


int Host::showerrinfo(int ret, const char* s) {
    if (ret < 0) {
        LOGE("%s: %s\n",s,strerror(errno));
    }
    return 1;
}


void Host::waitconnectHE(uint32_t events) {
    if( guest == NULL) {
        clean();
        return;
    }
    if (events & EPOLLOUT) {
        int error;
        socklen_t len=sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("getsokopt error: %s\n",strerror(error));
            clean();
            return;
        }
        if (error != 0) {
            LOGE( "connect to %s: %s\n",hostname, strerror(error));
            if(connect()<0) {
                clean();
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

    if( guest == NULL) {
        clean();
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

        if (ret <= 0 ){
            if(showerrinfo(ret,"host read error")) {
                clean();
                return;
            }
        }else{
            guest->Write(buff, ret);
        }

    }

    if (events & EPOLLOUT) {
        if (write_len) {
            int ret = Write();
            if (ret <= 0){
                if(showerrinfo(ret,"host write error")) {
                    clean();
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
        clean();
    }

}


void Host::Dnscallback(Host* host, const Dns_rcd&& rcd) {
    if(rcd.result!=0) {
        LOGE("Dns query failed\n");
        host->clean();
    } else {
        host->addr=rcd.addr;
        for(size_t i=0; i<host->addr.size(); ++i) {
            host->addr[i].addr_in6.sin6_port=htons(host->targetport);
        }
        if(host->connect()<0) {
            LOGE("connect to %s failed\n",host->hostname);
            host->clean();
        } else {
            epoll_event event;
            event.data.ptr=host;
            event.events=EPOLLOUT;
            epoll_ctl(host->efd,EPOLL_CTL_ADD,host->fd,&event);
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


void Host::clean() {
    if(guest) {
        guest->host=NULL;
        guest->clean();
    }
    guest=NULL;
    delete this;
}


Host* Host::gethost(Host* exist, const char* hostname, uint16_t port, int efd, Guest* guest) {
    if (exist == NULL) {
        return new Host(efd, guest,hostname,port);
    } else if (exist->targetport == port && strcasecmp(exist->hostname, hostname) == 0) {
        return exist;
    } else {
        Host* newhost = new Host(exist->efd, exist->guest,hostname,port);
        exist->clean();
        return newhost;
    }
}
