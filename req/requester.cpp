#include "requester.h"

#include <string.h>


Requester::Requester(const struct sockaddr_in6* myaddr) {
    if(myaddr){
        inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
        sourceport = ntohs(myaddr->sin6_port);
    }
}


Requester::Requester(const char* ip, uint16_t port):sourceport(port) {
    strcpy(sourceip, ip);
}

const char* Requester::getip(){
    return sourceip;
}
