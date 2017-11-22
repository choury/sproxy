#include "requester.h"

#include <string.h>


Requester::Requester(int fd, const struct sockaddr_in6* myaddr): Peer(fd) {
    if(myaddr){
        inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
        sourceport = ntohs(myaddr->sin6_port);

        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Requester::defaultHE;
    }
}


Requester::Requester(int fd, const char* ip, uint16_t port): Peer(fd), sourceport(port) {
    strcpy(sourceip, ip);
    
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Requester::defaultHE;
}



const char* Requester::getip(){
    return sourceip;
}


