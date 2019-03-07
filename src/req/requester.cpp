#include "requester.h"

#include <string.h>


Requester::Requester(const sockaddr_un* myaddr) {
    if(myaddr){
        switch(myaddr->addr.sa_family){
        case AF_INET:
            inet_ntop(AF_INET, &myaddr->addr_in.sin_addr, sourceip, sizeof(sourceip));
            sourceport = ntohs(myaddr->addr_in.sin_port);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &myaddr->addr_in6.sin6_addr, sourceip, sizeof(sourceip));
            sourceport = ntohs(myaddr->addr_in6.sin6_port);
            break;
        default:
            abort();
        }
    }
}


Requester::Requester(const char* ip, uint16_t port):sourceport(port) {
    strcpy(sourceip, ip);
}

const char* Requester::getip(){
    return sourceip;
}
