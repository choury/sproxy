#include "net.h"
#include "common.h"

#include <errno.h>
#include <string.h>
#include <strings.h>
//#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>


int Checksocket(int fd, const char *msg){
    int       error = 0;
    socklen_t errlen = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) != 0) {
        error = errno;
        LOGE("%s:getsockopt error: %s\n", msg, strerror(error));
    }else if(error){
        LOGE("%s:sock error: %s\n", msg, strerror(error));
    }
    return error;
}

void SetTcpOptions(int fd){
    //以下设置为TCP配置，非必须，所以不返回错误
    int keepAlive = 1; // 开启keepalive属性
    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive)) <0)
        LOGE("SO_KEEPALIVE:%s\n", strerror(errno));
#ifdef __APPLE__
   int secs = 30;
   if(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &secs, sizeof(secs)) < 0)
        LOGE("TCP_KEEPALIVE:%s\n", strerror(errno));
#else
    int idle = 60; //一分种没有交互就进行探测
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle))<0)
        LOGE("TCP_KEEPIDLE:%s\n", strerror(errno));
    int intvl = 10; //每10秒探测一次
    if(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl))<0)
        LOGE("TCP_KEEPINTVL:%s\n", strerror(errno));
    int cnt = 3; //探测3次无响应就关闭连接
    if(setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt))<0)
        LOGE("TCP_KEEPCNT:%s\n", strerror(errno));
#endif

    int enable = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enable, sizeof(enable))<0)
        LOGE("TCP_NODELAY:%s\n", strerror(errno));
}

int Listen(int type, short port) {
    int fd = socket(AF_INET6, type, 0);
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        if(protectFd(fd) == 0){
            LOGE("protecd fd error:%s\n", strerror(errno));
            break;
        }
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
            LOGE("setsockopt SO_REUSEADDR:%s\n", strerror(errno));
            break;
        }

#ifdef SO_REUSEPORT
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag)) < 0) {
            LOGE("setsockopt SO_REUSEPORT:%s\n", strerror(errno));
            break;
        }
#endif
        struct sockaddr_in6 myaddr;
        bzero(&myaddr, sizeof(myaddr));
        myaddr.sin6_family = AF_INET6;
        myaddr.sin6_port = htons(port);
        myaddr.sin6_addr = in6addr_any;

        if (bind(fd, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
            LOGE("bind error:%s\n", strerror(errno));
            break;
        }

        if(type == SOCK_STREAM){
#ifndef __APPLE__
            int timeout = 60;
            if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(timeout))< 0)
                LOGE("TCP_DEFER_ACCEPT:%s\n", strerror(errno));
#endif
            if (listen(fd, 10000) < 0) {
                LOGE("listen error:%s\n", strerror(errno));
                break;
            }
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}

int Bind(int type, short port, const union sockaddr_un* addr){
    int fd = socket(AF_INET6, type, 0);
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        if(protectFd(fd) == 0) {
            LOGE("protecd fd error:%s\n", strerror(errno));
            break;
        }
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
            LOGE("setsockopt SO_REUSEADDR:%s\n", strerror(errno));
            break;
        }
        struct sockaddr_in6 myaddr;
        bzero(&myaddr, sizeof(myaddr));
        myaddr.sin6_family = AF_INET6;
        myaddr.sin6_port = htons(port);
        myaddr.sin6_addr = in6addr_any;

        if (bind(fd, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
            LOGE("bind error:%s\n", strerror(errno));
            break;
        }

        if ((flag=fcntl(fd, F_GETFL)) == -1) {
            LOGE("fcntl get error:%s\n", strerror(errno));
            break;
        }

        if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1){
            LOGE("fcntl set error:%s\n", strerror(errno));
            break;
        }

        if(type == SOCK_STREAM){
            SetTcpOptions(fd);
        }else{
            if(addr->addr.sa_family == AF_INET && addr->addr_in.sin_addr.s_addr == htonl(INADDR_BROADCAST)){
                int enable=1;
                if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0){
                    LOGE("set broadcast:%s\n", strerror(errno));
                    break;
                }
            }
        }

        socklen_t len = (addr->addr.sa_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (connect(fd, &addr->addr, len) == -1 && errno != EINPROGRESS) {
            LOGE("connecting error:%s\n", strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}


int Connect(const union sockaddr_un* addr, int type) {
    int fd =  socket(addr->addr.sa_family, type, 0);
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n", strerror(errno));
            break;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if(protectFd(fd) == 0){
            LOGE("protecd fd error:%s\n", strerror(errno));
            break;
        }

        if(type == SOCK_STREAM){
            SetTcpOptions(fd);
        }else{
            if(addr->addr.sa_family == AF_INET && addr->addr_in.sin_addr.s_addr == htonl(INADDR_BROADCAST)){
                int enable=1;
                if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0){
                    LOGE("set broadcast:%s\n", strerror(errno));
                    break;
                }
            }
        }

        socklen_t len = (addr->addr.sa_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (connect(fd, &addr->addr, len) == -1 && errno != EINPROGRESS) {
            LOGE("connecting %s error:%s\n", getaddrportstring(addr), strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}


int IcmpSocket(const union sockaddr_un* addr){
    int fd = -1;
    if(addr->addr.sa_family == AF_INET){
#ifdef SOCK_CLOEXEC
        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMP);
#else
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#endif
        if(fd <= 0){
            LOGE("create icmp socket failed: %s\n", strerror(errno));
            return -1;
        }
    }
    if(addr->addr.sa_family == AF_INET6){
#ifdef SOCK_CLOEXEC
        fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_ICMPV6);
#else
        fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
#endif
        if(fd <= 0){
            LOGE("create icmp6 socket failed: %s\n", strerror(errno));
            return -1;
        }
    }

    if(protectFd(fd) == 0){
        LOGE("protecd fd error:%s\n", strerror(errno));
        goto ERR;
    }
    socklen_t len = (addr->addr.sa_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
    if(connect(fd, &addr->addr, len)){
        LOGE("connect failed: %s\n", strerror(errno));
        goto ERR;
    }

    time_t time = 1;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &time, sizeof(time));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &time, sizeof(time));
    return fd;
ERR:
    close(fd);
    return -1;
}

const char *getaddrstring(const union sockaddr_un *addr){
    static char buff[100];
    if(addr->addr.sa_family == AF_INET6){
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr->addr_in6.sin6_addr, ip, sizeof(ip));
        sprintf(buff, "[%s]", ip);
    }
    if(addr->addr.sa_family == AF_INET){
        inet_ntop(AF_INET, &addr->addr_in.sin_addr, buff, sizeof(buff));
    }
    return buff;
}


const char *getaddrportstring(const union sockaddr_un *addr){
    static char buff[100];
    char ip[INET6_ADDRSTRLEN];
    if(addr->addr.sa_family == AF_INET6){
        inet_ntop(addr->addr.sa_family, &addr->addr_in6.sin6_addr, ip, sizeof(ip));
        sprintf(buff, "[%s]:%d", ip, ntohs(addr->addr_in6.sin6_port));
    }
    if(addr->addr.sa_family == AF_INET){
        inet_ntop(AF_INET, &addr->addr_in.sin_addr, ip, sizeof(ip));
        sprintf(buff, "%s:%d", ip, ntohs(addr->addr_in.sin_port));
    }
    return buff;
}


#ifndef __ANDROID__
#include <ifaddrs.h>
#define INTERFACE_MAX 50
union sockaddr_un* getlocalip () {
    struct ifaddrs *ifap, *ifa;
    static union sockaddr_un ips[INTERFACE_MAX];
    memset(ips, 0, sizeof(ips));
    getifaddrs (&ifap);
    int i = 0;
    for (ifa = ifap; ifa && i < INTERFACE_MAX; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr == NULL)
            continue;
        memcpy(&ips[i++], ifa->ifa_addr, sizeof(struct sockaddr_in6));
    }
    freeifaddrs(ifap);
    return ips;
}
#else
union sockaddr_un* getlocalip (){
    static union sockaddr_un ip;
    memset(&ip, 0, sizeof(ip));
    return &ip;
}
#endif

