#include "guest_sni.h"
#include "host.h"
#include "tls.h"
#include "dns.h"

#include <string.h>
#include <arpa/inet.h>

Guest_sni::Guest_sni(int fd, sockaddr_in6 *myaddr):Peer(fd){
    inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
    sourceport = ntohs(myaddr->sin6_port);


    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_sni::initHE;
}


int Guest_sni::showerrinfo(int ret, const char *) {

}


void Guest_sni::initHE(uint32_t events) {
    if(events & EPOLLIN){
        int ret=read(fd, rbuff+readlen, sizeof(rbuff)-readlen);
        if(ret <= 0){
            if (showerrinfo(ret, "guest_sni read error")) {
                close();
            }
            return;
        }
        readlen += ret;
        char *hostname;
        ret = parse_tls_header(rbuff, readlen, &hostname);
        if(ret > 0){
            LOG("([%s]%d): Sni:%s\n", sourceip, sourceport, hostname);
            char buff[HEADLENLIMIT];
            sprintf(buff, "CONNECT %s:%d"CRLF, hostname, 443);
            HttpReqHeader req(buff);
            Host::gethost(req, this);
//            query(hostname, (DNSCBfunc)Guest_sni::Dnscallback, this);
        }else if(ret != -1){
            close();
        }
    }
}


void Guest_sni::defaultHE(uint32_t events){
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        close();
        return;
    }
}

void Guest_sni::closeHE(uint32_t events) {

}



void Guest_sni::close()
{

}
