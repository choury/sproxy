#define __APPLE_USE_RFC_3542
#define _GNU_SOURCE
#include "net.h"
#include "common/common.h"
#include "misc/util.h"

#include <errno.h>
#include <string.h>
#include <strings.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/un.h>

int Checksocket(int fd, const char *msg){
    int       error = 0;
    socklen_t errlen = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) != 0) {
        error = errno;
        LOGE("%s:getsockopt error [%d]: %s\n", msg, fd, strerror(error));
    }else if(error){
        LOGE("%s:sock error [%d]: %s\n", msg, fd, strerror(error));
    }
    return error;
}

void SetSocketUnblock(int fd){
    if(fd < 0){
        return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if(flags < 0){
        LOGF("fcntl error [%d]: %s\n", fd, strerror(errno));
    }
    if(flags & O_NONBLOCK) {
        return;
    }
    int ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    if(ret < 0){
        LOGF("fcntl error [%d]: %s\n", fd, strerror(errno));
    }
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

    SetSocketUnblock(fd);
}

void SetUdpOptions(int fd, const struct sockaddr_storage* addr){
    (void)addr;
    int enable = 1;
#if defined(IP_RECVERR)
    if (addr->ss_family == AF_INET) {
        if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enable, sizeof(enable)))
            LOGE("IP_RECVERR:%s\n", strerror(errno));
        if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &enable, sizeof(enable)))
            LOGE("IP_MTU_DISCOVER:%s\n", strerror(errno));
    }
#endif
#if defined(IPV6_RECVERR)
    if (addr->ss_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &enable, sizeof(enable)))
            LOGE("IPV6_RECVERR:%s\n", strerror(errno));
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &enable, sizeof(enable)))
            LOGE("IPV6_MTU_DISCOVER:%s\n", strerror(errno));
    }
#endif
#if defined(IP_DONTFRAG)
    if(addr->ss_family == AF_INET)
        if(setsockopt(fd, IPPROTO_IP, IP_DONTFRAG, &enable, sizeof(enable)))
            LOGE("IP_DONTFRAG:%s\n", strerror(errno));
    if(addr->ss_family == AF_INET6)
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_DONTFRAG, &enable, sizeof(enable)))
            LOGE("IPV6_DONTFRAG:%s\n", strerror(errno));
#endif
    if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0)
        LOGE("set broadcast:%s\n", strerror(errno));
    SetSocketUnblock(fd);
}

void SetIcmpOptions(int fd, const struct sockaddr_storage* addr) {
    (void)addr;
    int enable = 1;
#if defined(IP_RECVERR)
    if (addr->ss_family == AF_INET) {
        if (setsockopt(fd, IPPROTO_IP, IP_RECVERR, &enable, sizeof(enable)))
            LOGE("IP_RECVERR:%s\n", strerror(errno));
    }
#endif
#if defined(IPV6_RECVERR)
    if (addr->ss_family == AF_INET6) {
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVERR, &enable, sizeof(enable)))
            LOGE("IPV6_RECVERR:%s\n", strerror(errno));
    }
#endif
    if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0)
        LOGE("set broadcast:%s\n", strerror(errno));
    SetSocketUnblock(fd);
}

void PadUnixPath(struct sockaddr_storage* addr, socklen_t len) {
    if(addr->ss_family != AF_UNIX) {
        return;
    }
    struct sockaddr_un* un = (struct sockaddr_un*)addr;
    size_t sun_len = len - (long)&((struct sockaddr_un*)0)->sun_path;
    memset(un->sun_path + sun_len, 0, sizeof(un->sun_path) - sun_len);
}

void SetUnixOptions(int fd, const struct sockaddr_storage* addr) {
    (void)addr;
    SetSocketUnblock(fd);
}

void SetRecvPKInfo(int fd, const struct sockaddr_storage* addr) {
    int enable = 1;
#if __linux__
    if(addr->ss_family == AF_INET || isAnyAddress(addr)) {
        if(setsockopt(fd, IPPROTO_IP, IP_RECVORIGDSTADDR, &enable, sizeof(enable)) < 0) {
            LOGF("setsockopt IP_RECVORIGDSTADD:%s\n", strerror(errno));
        }
    }
    if(addr->ss_family == AF_INET6 || isAnyAddress(addr)) {
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &enable, sizeof(enable)) < 0) {
            LOGF("setsockopt IPV6_RECVORIGDSTADD:%s\n", strerror(errno));
        }
    }
#else
    if(addr->ss_family == AF_INET) {
        if(setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &enable, sizeof(enable)) < 0){
            LOGF("setsockopt IP_PKTINFO:%s\n", strerror(errno));
        }
    }
    if(addr->ss_family == AF_INET6) {
        if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &enable, sizeof(enable)) < 0){
            LOGF("setsockopt IPV6_PKTINFO:%s\n", strerror(errno));
        }
    }
#endif
}

size_t GetCapSize(int fd) {
    size_t sndbuf;
    socklen_t len = sizeof(sndbuf);
    if(getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &len) < 0){
        LOGE("failed to get sndbuf for %d: %s\n", fd, strerror(errno));
        return 0;
    }
    return sndbuf;
}

size_t GetBuffSize(int fd){
    size_t outq = 0;
#if __linux__
    if(ioctl(fd, TIOCOUTQ, &outq) < 0){
        LOGE("ioctl failed for %d: %s\n", fd, strerror(errno));
        return BUF_LEN;
    }
#elif __APPLE__
    socklen_t outq_len = sizeof(outq);
    if (getsockopt(fd, SOL_SOCKET, SO_NWRITE, &outq, &outq_len) < 0) {
        LOGE("getsockopt failed for %d: %s\n", fd, strerror(errno));
        return BUF_LEN;
    }
#endif
    return outq;
}

int ListenTcp(const struct sockaddr_storage* addr, const struct listenOption* ops) {
    (void)ops;
#ifdef  SOCK_CLOEXEC
    int fd = socket(addr->ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(addr->ss_family, SOCK_STREAM, 0);
#endif
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
            LOGE("setsockopt SO_REUSEADDR:%s\n", strerror(errno));
            break;
        }

        socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (bind(fd, (struct sockaddr*)addr, len) < 0) {
            LOGE("bind error:%s\n", strerror(errno));
            break;
        }

#ifndef __APPLE__
        if(ops == NULL || !ops->disable_defer_accepct) {
            int timeout = 60;
            if (setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(timeout))< 0)
                LOGE("TCP_DEFER_ACCEPT:%s\n", strerror(errno));
        }
        if(ops != NULL && ops->enable_ip_transparent) {
            if(addr->ss_family == AF_INET)
                if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(enable)) < 0)
                    LOGE("IP_TRANSPARENT:%s\n", strerror(errno));
            if(addr->ss_family == AF_INET6)
                if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &enable, sizeof(enable)) < 0)
                    LOGE("IPV6_TRANSPARENT:%s\n", strerror(errno));
        }
#endif
        if (listen(fd, 10000) < 0) {
            LOGE("listen error:%s\n", strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}


int ListenUdp(const struct sockaddr_storage* addr, const struct listenOption* ops) {
    (void)ops;
#ifdef  SOCK_CLOEXEC
    int fd = socket(addr->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(addr->ss_family, SOCK_DGRAM, 0);
#endif
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        int enable = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0) {
            LOGE("setsockopt SO_REUSEADDR:%s\n", strerror(errno));
            break;
        }

#ifdef __APPLE__
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) < 0) {
            LOGE("setsockopt SO_REUSEPORT:%s\n", strerror(errno));
            break;
        }
#else
        if(ops != NULL && ops->enable_ip_transparent) {
            if(addr->ss_family == AF_INET)
                if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &enable, sizeof(enable)) < 0)
                    LOGE("IP_TRANSPARENT:%s\n", strerror(errno));
            if(addr->ss_family == AF_INET6)
                if (setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &enable, sizeof(enable)) < 0)
                    LOGE("IPV6_TRANSPARENT:%s\n", strerror(errno));
        }
#endif
        socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (bind(fd, (struct sockaddr*)addr, len) < 0) {
            LOGE("bind error:%s\n", strerror(errno));
            break;
        }
        SetRecvPKInfo(fd, addr);
        return fd;
    }while(0);
    close(fd);
    return -1;
}

int ListenUnix(const char* path, const struct listenOption* ops) {
    (void)ops;
#ifdef SOCK_CLOEXEC
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
#else
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
#endif
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
#ifdef SO_PASSCRED
        int flag = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &flag, sizeof(flag)) < 0) {
            LOGE("setsockopt SO_PASSCRED:%s\n", strerror(errno));
            break;
        }
#endif

        struct sockaddr_un myaddr;
        bzero(&myaddr, sizeof(myaddr));
        myaddr.sun_family = AF_UNIX;
        if(path[0] == '@'){
            myaddr.sun_path[0] = '\0';
        }else{
            unlink(path);
            myaddr.sun_path[0] = path[0];
        }
        char* end = stpcpy(myaddr.sun_path+1, path+1);

        if (bind(fd, (struct sockaddr*)&myaddr, end - (char*)&myaddr) < 0) {
            LOGE("bind error %s:%s\n", path, strerror(errno));
            break;
        }

        if (listen(fd, 10000) < 0) {
            LOGE("listen error:%s\n", strerror(errno));
            break;
        }
        return fd;
    }while(0);
    close(fd);
    return -1;
}

int Connect(const struct sockaddr_storage* addr, int type) {
#ifdef SOCK_CLOEXEC
    int fd =  socket(addr->ss_family, type | SOCK_CLOEXEC, 0);
#else
    int fd =  socket(addr->ss_family, type, 0);
#endif
    if (fd < 0) {
        LOGE("socket error:%s\n", strerror(errno));
        return -1;
    }
    do{
        if(protectFd(fd) == 0){
            LOGE("protecd fd %d error:%s\n", fd, strerror(errno));
            break;
        }

        switch(addr->ss_family){
        case AF_INET:
        case AF_INET6:
            if(type == SOCK_STREAM){
                SetTcpOptions(fd, addr);
            }else{
                SetUdpOptions(fd, addr);
            }
            break;
        default:
            LOGF("unkown family: %d\n", addr->ss_family);
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

int IcmpSocket(const struct sockaddr_storage* addr, int raw){
    int fd = -1;
    int type = raw?SOCK_RAW:SOCK_DGRAM;
#ifdef SOCK_CLOEXEC
    type |= SOCK_CLOEXEC;
#endif

    if(addr->ss_family == AF_INET){
        fd = socket(AF_INET, type, IPPROTO_ICMP);
        if(fd <= 0){
            LOGE("create icmp socket failed: %s\n", strerror(errno));
            return -1;
        }
    }
    if(addr->ss_family == AF_INET6){
        fd = socket(AF_INET6, type, IPPROTO_ICMPV6);
        if(fd <= 0){
            LOGE("create icmp6 socket failed: %s\n", strerror(errno));
            return -1;
        }
    }

    if(protectFd(fd) == 0){
        LOGE("protecd fd error:%s\n", strerror(errno));
        goto ERR;
    }
    SetIcmpOptions(fd, addr);
    socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
    if(connect(fd, (struct sockaddr*)addr, len)){
        LOGE("connect failed: %s\n", strerror(errno));
        goto ERR;
    }
    return fd;
ERR:
    close(fd);
    return -1;
}

ssize_t recvwithaddr(int fd, void* buff, size_t buflen,
                     struct sockaddr_storage* myaddr,
                     struct sockaddr_storage* hisaddr)
{
    struct iovec iov;
    iov.iov_base = buff;
    iov.iov_len = buflen;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    memset(hisaddr, 0, sizeof(*hisaddr));
    msg.msg_name = hisaddr;
    msg.msg_namelen = sizeof(*hisaddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char controlbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
                    CMSG_SPACE(sizeof(struct in_pktinfo)) +
                    CMSG_SPACE(sizeof(struct sockaddr_in)) +
                    CMSG_SPACE(sizeof(struct sockaddr_in6))];
    msg.msg_control = controlbuf;
    msg.msg_controllen = sizeof(controlbuf);

    ssize_t ret = recvmsg(fd, &msg, 0);
    if(ret < 0){
        LOGE("recvfrom error: %s\n", strerror(errno));
        return ret;
    }
    memset(myaddr, 0, sizeof(*myaddr));
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef __linux__
        if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_ORIGDSTADDR) {
            memcpy(myaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in6));
            break;
        }
        if(cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_ORIGDSTADDR) {
            memcpy(myaddr, CMSG_DATA(cmsg), sizeof(struct sockaddr_in));
            break;
        }
#endif
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *info6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            struct sockaddr_in6* myaddr6 = (struct sockaddr_in6*)myaddr;
            myaddr6->sin6_family = AF_INET6;
            myaddr6->sin6_addr = info6->ipi6_addr;
        } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *info = (struct in_pktinfo *) CMSG_DATA(cmsg);
            struct sockaddr_in* myaddr4 = (struct sockaddr_in*)myaddr;
            myaddr4->sin_family = AF_INET;
            myaddr4->sin_addr = info->ipi_addr;
        } else {
            LOGE("unknown level: %d or type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
            return -1;
        }
    }
    if(myaddr->ss_family == AF_UNSPEC) {
        LOGE("can't get IP_PKTINFO\n");
        return -1;
    }
    if(myaddr->ss_family == AF_INET  && hisaddr->ss_family == AF_INET6) {
        // ipv4 -> ipv6
        hisaddr->ss_family = AF_INET;
        ((struct sockaddr_in*)hisaddr)->sin_addr = getMapped(((struct sockaddr_in6*)hisaddr)->sin6_addr, IPV4MAPIPV6);
    }
    return ret;
}

void addrstring(const struct sockaddr_storage* addr, char* buff, size_t len) {
    memset(buff, 0, len);
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    struct sockaddr_un* addrunix = (struct sockaddr_un*)addr;
    if(addr->ss_family == AF_INET6){
        struct in_addr ip4 = getMapped(addr6->sin6_addr, IPV4MAPIPV6);
        if(ip4.s_addr != INADDR_NONE){
            inet_ntop(AF_INET, &ip4, buff, len);
        }else {
            buff[0] = '[';
            inet_ntop(AF_INET6, &addr6->sin6_addr, buff + 1, len -1);
            buff[strlen(buff)] = ']';
        }
    }else if(addr->ss_family == AF_INET){
        inet_ntop(AF_INET, &addr4->sin_addr, buff, len);
    }else if(addr->ss_family == AF_UNIX) {
        if(addrunix->sun_path[0] == 0 ) {
            buff[0] = '@';
        } else {
            buff[0] = addrunix->sun_path[0];
        }
        snprintf(buff + 1, len - 1 , "%s", addrunix->sun_path+1);
    }
}

const char *getaddrstring(const struct sockaddr_storage *addr){
    static char buff[108];
    addrstring(addr, buff, sizeof(buff));
    return buff;
}


const char *storage_ntoa(const struct sockaddr_storage *addr){
    static char buff[108];
    addrstring(addr, buff, sizeof(buff));
    size_t len = strlen(buff);
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    if(addr->ss_family == AF_INET6){
        snprintf(buff + len, sizeof(buff) - len, ":%d", ntohs(addr6->sin6_port));
    }else if(addr->ss_family == AF_INET){
        snprintf(buff + len, sizeof(buff) - len, ":%d", ntohs(addr4->sin_port));
    }
    return buff;
}

int storage_aton(const char* ipstr, uint16_t port, struct sockaddr_storage* addr){
    char host[INET6_ADDRSTRLEN] = {0};
    if(ipstr[0] == '['){ //may be ipv6 of format as [2001::1]
        snprintf(host, sizeof(host), "%s", ipstr+1);
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
        addr6->sin6_family = AF_INET6;
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

#define INTERFACE_MAX 100
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
    struct sockaddr_storage ip;
    memset(&ip, 0, sizeof(ip));
    storage_aton("2001:4860::1", 1, &ip);
    int fd = Connect(&ip, SOCK_STREAM);
    if(fd < 0) return false;
    socklen_t len = sizeof(ip);
    if(getsockname(fd, (struct sockaddr*)&ip, &len) < 0){
        LOGE("getsockname failed: %s\n", strerror(errno));
        close(fd);
        return false;
    }
    close(fd);
    struct sockaddr_in6* ip6 = (struct sockaddr_in6*)&ip;
    return (ip6->sin6_addr.s6_addr[0]&0x70) == 0x20;
}

bool isLocalIp(const struct sockaddr_storage* addr){
    for(struct sockaddr_storage* ips=getlocalip(); ips->ss_family ; ips++){
        if(ips->ss_family != addr->ss_family) continue;
        if(ips->ss_family == AF_INET){
            struct sockaddr_in* ip4 = (struct sockaddr_in*)ips;
            struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
            if(ip4->sin_addr.s_addr == addr4->sin_addr.s_addr){
                return true;
            }
        }else if(ips->ss_family == AF_INET6){
            struct sockaddr_in6* ip6 = (struct sockaddr_in6*)ips;
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
            if(memcmp(&ip6->sin6_addr, &addr6->sin6_addr, sizeof(struct in6_addr)) == 0){
                return true;
            }
        }
    }
    return false;
}

bool isLoopBack(const struct sockaddr_storage* addr) {
    if(addr->ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        return addr4->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    }
    if(addr->ss_family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
        return IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr);
    }
    return false;
}

bool isAnyAddress(const struct sockaddr_storage* addr) {
    if(addr->ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        return addr4->sin_addr.s_addr == htonl(INADDR_ANY);
    }
    if(addr->ss_family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
        return IN6_IS_ADDR_UNSPECIFIED(&addr6->sin6_addr);
    }
    return false;
}

bool isBroadcast(const struct sockaddr_storage* addr) {
    if(addr->ss_family == AF_INET) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        return addr4->sin_addr.s_addr == htonl(INADDR_BROADCAST);
    }
    if(addr->ss_family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
        return IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr);
    }
    return false;
}
