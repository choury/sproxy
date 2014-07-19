#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "net.h"




int ConnectTo(const char* host, int port,char *targetip){
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
    
    if(targetip){
        inet_ntop(res->ai_family, &res->ai_addr, targetip, INET6_ADDRSTRLEN);
    }
    
    int fd;
    if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
        perror("socket error");
        freeaddrinfo(res);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl error");
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    if (connect(fd, res->ai_addr, res->ai_addrlen) == -1 && errno != EINPROGRESS) {
        perror("connecting error");
        freeaddrinfo(res);
        close(fd);
        return -1;
    }

    freeaddrinfo(res);
    return fd;
}