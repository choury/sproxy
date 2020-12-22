#include "net.h"
#include "common.h"
#include "misc/util.h"

#include <errno.h>
#include <string.h>
#include <strings.h>

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

void SetTcpOptions(int fd, const struct sockaddr_storage* ignore){
    (void)ignore;
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

void SetUdpOptions(int fd, const struct sockaddr_storage* addr){
    int enable = 1;
#if defined(IP_RECVERR) && defined(IPV6_RECVERR)
    if (addr->ss_family == AF_INET) {
        if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enable, sizeof(enable)))
            LOGE("IP_RECVERR:%s\n", strerror(errno));
    }
    if (addr->ss_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &enable, sizeof(enable)))
            LOGE("IPV6_RECVERR:%s\n", strerror(errno));
    }
#endif
    if(addr->ss_family == AF_INET && ((struct sockaddr_in*)addr)->sin_addr.s_addr == htonl(INADDR_BROADCAST)){
        if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0)
            LOGE("set broadcast:%s\n", strerror(errno));
    }
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

int Bind(int type, short port, const struct sockaddr_storage* addr){
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
            SetTcpOptions(fd, addr);
        }else{
            SetUdpOptions(fd, addr);
        }

        socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (connect(fd, (struct sockaddr*)addr, len) == -1 && errno != EINPROGRESS) {
            LOGE("connecting error:%s\n", strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}


int Connect(const struct sockaddr_storage* addr, int type) {
    int fd =  socket(addr->ss_family, type, 0);
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        if(protectFd(fd) == 0){
            LOGE("protecd fd error:%s\n", strerror(errno));
            break;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n", strerror(errno));
            break;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        if(type == SOCK_STREAM){
            SetTcpOptions(fd, addr);
        }else{
            SetUdpOptions(fd, addr);
        }

        socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (connect(fd, (struct sockaddr*)addr, len) == -1 && errno != EINPROGRESS) {
            LOGE("connecting %s error: %s\n", storage_ntoa(addr), strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}


int IcmpSocket(const struct sockaddr_storage* addr){
    int fd = -1;
    if(addr->ss_family == AF_INET){
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
    if(addr->ss_family == AF_INET6){
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
    socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
    if(connect(fd, (struct sockaddr*)addr, len)){
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

const char *getaddrstring(const struct sockaddr_storage *addr){
    static char buff[100];
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    if(addr->ss_family == AF_INET6){
        struct in_addr ip4 = getMapped(addr6->sin6_addr, IPV4MAPIPV6);
        if(ip4.s_addr != INADDR_NONE){
            inet_ntop(AF_INET, &ip4, buff, sizeof(buff));
        }else {
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr6->sin6_addr, ip, sizeof(ip));
            sprintf(buff, "[%s]", ip);
        }
    }else if(addr->ss_family == AF_INET){
        inet_ntop(AF_INET, &addr4->sin_addr, buff, sizeof(buff));
    }
    return buff;
}


const char *storage_ntoa(const struct sockaddr_storage *addr){
    static char buff[100];
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    if(addr->ss_family == AF_INET6){
        struct in_addr ip4 = getMapped(addr6->sin6_addr, IPV4MAPIPV6);
        if(ip4.s_addr != INADDR_NONE){
            inet_ntop(AF_INET, &ip4, ip, sizeof(ip));
            sprintf(buff, "%s:%d", ip, ntohs(addr4->sin_port));
        }else{
            inet_ntop(AF_INET6, &addr6->sin6_addr, ip, sizeof(ip));
            sprintf(buff, "[%s]:%d", ip, ntohs(addr4->sin_port));
        }
    }else if(addr->ss_family == AF_INET){
        inet_ntop(AF_INET, &addr4->sin_addr, ip, sizeof(ip));
        sprintf(buff, "%s:%d", ip, ntohs(addr4->sin_port));
    }
    return buff;
}

int storage_aton(const char* ipstr, uint16_t port, struct sockaddr_storage* addr){
    char host[INET6_ADDRSTRLEN] = {0};
    if(ipstr[0] == '['){ //may be ipv6 of format as [2001::1]
        strncpy(host, ipstr + 1, sizeof(host)-1);
        *strchrnul(host, ']') = 0;
        ipstr = host;
    }

    memset(addr, 0, sizeof(struct sockaddr_storage));
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    if (inet_pton(AF_INET, ipstr, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        return 1;
    }
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    if (inet_pton(AF_INET6, ipstr, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET;
        addr6->sin6_port = htons(port);
        return 1;
    }
    return 0;
}


#include <ifaddrs.h>
#if defined(ANDROID) && __ANDROID_API__ < 24
int getifaddrs(struct ifaddrs** __list_ptr);
void freeifaddrs(struct ifaddrs* __ptr);
#endif

#define INTERFACE_MAX 50
struct sockaddr_storage* getlocalip () {
    struct ifaddrs *ifap, *ifa;
    static struct sockaddr_storage ips[INTERFACE_MAX];
    memset(ips, 0, sizeof(ips));
    getifaddrs(&ifap);
    int i = 0;
    for (ifa = ifap; ifa && i < INTERFACE_MAX; ifa = ifa->ifa_next) {
        if(ifa->ifa_addr == NULL)
            continue;
        memcpy(&ips[i++], ifa->ifa_addr, sizeof(struct sockaddr_in6));
    }
    freeifaddrs(ifap);
    return ips;
}

bool hasIpv6Address(){
    struct sockaddr_storage* ips;
    for(ips = getlocalip(); ips->ss_family ; ips++){
        struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ips;
        if(ips->ss_family == AF_INET6 && (ip6->sin6_addr.s6_addr[0]&0x70) == 0x20){
            return true;
        }
    }
    return false;
}

