#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "net.h"



int Connect(struct sockaddr* addr) {
    int fd;
    if ((fd = socket(addr->sa_family,SOCK_STREAM , 0)) < 0) {
        perror("socket error");
        return -1;
    }
    
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl error");
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (connect(fd, addr, sizeof(struct sockaddr_in6)) == -1 && errno != EINPROGRESS) {
        perror("connecting error");
        close(fd);
    }
    
    return fd;
}



int ConnectTo(const char* host, int port){
    struct addrinfo hints, *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    char buff[20];
    sprintf(buff, "%d", port);
    int s;
    if ((s=getaddrinfo(host, buff, &hints, &res))) {
       fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    int fd;
    struct addrinfo *curinfo=res;
    while(curinfo){
        if ((fd = socket(curinfo->ai_family, curinfo->ai_socktype, curinfo->ai_protocol)) < 0) {
            perror("socket error");
            freeaddrinfo(res);
            return -1;
        }
        struct timeval timeo = {30, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
        if (connect(fd, curinfo->ai_addr, curinfo->ai_addrlen) == -1) {
            perror("connecting error");
            close(fd);
        }else{
            break;
        }
        curinfo=curinfo->ai_next;
    }

    freeaddrinfo(res);
    if(curinfo == NULL){
        return -1;
    }else{
        return fd;
    }
}
