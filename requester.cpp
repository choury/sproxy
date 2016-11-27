#include "requester.h"


Requester::Requester(int fd, struct sockaddr_in6* myaddr): Peer(fd) {
    inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
    sourceport = ntohs(myaddr->sin6_port);

    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Requester::defaultHE;
}


Requester::Requester(int fd, const char* ip, uint16_t port): Peer(fd), sourceport(port) {
    strcpy(sourceip, ip);
    
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Requester::defaultHE;
}

void Requester::closeHE(uint32_t events) {
    int ret = Peer::Write_buff();
    if (ret != WRITE_INCOMP ||
        (ret <= 0 && showerrinfo(ret, "write error while closing"))) {
        delete this;
        return;
    }
}


void Requester::ResetResponser(Responser* , uint32_t) {
}

const char* Requester::getip(){
    return sourceip;
}

const char* Requester::getsrc(){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d", sourceip, sourceport);
    return src;
}

