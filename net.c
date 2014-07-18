#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include "net.h"


int spliturl(const char* url, char* host, char* path , int* port)
{
    char* addrsplit;
    char tmpaddr[DOMAINLIMIT];
    int urllen = strlen(url);
    int copylen;
    bzero(host, DOMAINLIMIT);
    bzero(path, urllen);
    if (strncasecmp(url, "https://", 8) == 0) {
        url += 8;
        urllen -= 8;
        *port = HTTPSPORT;
    } else if (strncasecmp(url, "http://", 7) == 0) {
        url += 7;
        urllen -= 7;
        *port = HTTPPORT;
    } else if (!strstr(url, "://")) {
        *port = HTTPPORT;
    } else {
        return -1;
    }

    if ((addrsplit = strpbrk(url, "/"))) {
        copylen = url + urllen - addrsplit < (URLLIMIT - 1) ? url + urllen - addrsplit : (URLLIMIT - 1);
        memcpy(path, addrsplit, copylen);
        copylen = addrsplit - url < (DOMAINLIMIT - 1) ? addrsplit - url : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        tmpaddr[copylen] = 0;
    } else {
        copylen = urllen < (DOMAINLIMIT - 1) ? urllen : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        strcpy(path, "/");
        tmpaddr[copylen] = 0;
    }

    if (tmpaddr[0] == '[') {                                //this is a ipv6 address
        if (!(addrsplit = strpbrk(tmpaddr, "]"))) {
            return -1;
        }

        strncpy(host, tmpaddr + 1, addrsplit - tmpaddr - 1);
        if (addrsplit[1] == ':') {
            if(sscanf(addrsplit + 2, "%d", port)!=1)
                return -1;
        } else if (addrsplit[1] != 0) {
            return -1;
        }
    } else {
        if ((addrsplit = strpbrk(tmpaddr, ":"))) {
            strncpy(host, url, addrsplit - tmpaddr);
            if(sscanf(addrsplit + 1, "%d", port)!=1)
                return -1;
        } else {
            strcpy(host, tmpaddr);
        }
    }

    return 0;
}



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