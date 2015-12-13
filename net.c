#include "net.h"
#include "common.h"

#include <errno.h>
#include <string.h>
#include <strings.h>

#include <unistd.h>
#include <fcntl.h>
#include <netinet/tcp.h>


const char *DEFAULT_CIPHER_LIST = 
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:"
            "kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:"
            "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:"
            "ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:"
            "DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:"
            "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";


int Listen(int type, short port) {
    int svsk;
    if ((svsk = socket(AF_INET6, type, 0)) < 0) {
        LOGOUT("socket error:%s\n", strerror(errno));
        return -1;
    }

    int flag = 1;

    if (setsockopt(svsk, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        LOGOUT("setsockopt:%s\n", strerror(errno));
        return -2;
    }

    struct sockaddr_in6 myaddr;
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin6_family = AF_INET6;
    myaddr.sin6_port = htons(port);
    myaddr.sin6_addr = in6addr_any;

    if (bind(svsk, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
        LOGOUT("bind error:%s\n", strerror(errno));
        return -3;
    }
    
    //以下设置为keealive配置，非必须，所以不返回错误
    int keepAlive = 1; // 开启keepalive属性
    if(setsockopt(svsk, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive)) <0)
        LOGE("SO_KEEPALIVE:%s\n",strerror(errno));
    int idle = 60; //一分种没有交互就进行探测
    if(setsockopt(svsk, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle))<0)
        LOGE("TCP_KEEPIDLE:%s\n",strerror(errno));
    int intvl = 10; //每10秒探测一次
    if(setsockopt(svsk, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl))<0)
        LOGE("TCP_KEEPINTVL:%s\n",strerror(errno));
    int cnt = 3; //探测3次无响应就关闭连接
    if(setsockopt(svsk, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt))<0)
        LOGE("TCP_KEEPCNT:%s\n",strerror(errno));

    int enable = 1;
    if(setsockopt(svsk, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable))<0)
        LOGE("TCP_NODELAY:%s\n", strerror(errno));
    
    if (listen(svsk, 10000) < 0) {
        LOGOUT("listen error:%s\n", strerror(errno));
        return -4;
    }
    return svsk;
}


int Connect(struct sockaddr* addr) {
    int fd;
    if ((fd = socket(addr->sa_family,SOCK_STREAM , 0)) < 0) {
        LOGE("socket error:%s\n",strerror(errno));
        return -1;
    }
    
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        LOGE("fcntl error:%s\n",strerror(errno));
        close(fd);
        return -1;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    //以下设置为keealive配置，非必须，所以不返回错误
    int keepAlive = 1; // 开启keepalive属性
    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive)) <0)
        LOGE("SO_KEEPALIVE:%s\n",strerror(errno));
    int idle = 60; //一分种没有交互就进行探测
    if(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle))<0)
        LOGE("TCP_KEEPIDLE:%s\n",strerror(errno));
    int intvl = 10; //每10秒探测一次
    if(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl))<0)
        LOGE("TCP_KEEPINTVL:%s\n",strerror(errno));
    int cnt = 3; //探测3次无响应就关闭连接
    if(setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt))<0)
        LOGE("TCP_KEEPCNT:%s\n",strerror(errno));
    
    int enable = 1;
    if(setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&enable, sizeof(enable))<0)
        LOGE("TCP_NODELAY:%s\n", strerror(errno));
    
    if (connect(fd, addr, sizeof(struct sockaddr_in6)) == -1 && errno != EINPROGRESS) {
        LOGE("connecting error:%s\n",strerror(errno));
        close(fd);
        return -1;
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
       LOGE( "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    int fd;
    struct addrinfo *curinfo=res;
    while(curinfo){
        if ((fd = socket(curinfo->ai_family, curinfo->ai_socktype, curinfo->ai_protocol)) < 0) {
            LOGE("socket error:%s\n",strerror(errno));
            freeaddrinfo(res);
            return -1;
        }
        struct timeval timeo = {30, 0};
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));
        if (connect(fd, curinfo->ai_addr, curinfo->ai_addrlen) == -1) {
            LOGE("connecting error:%s\n",strerror(errno));
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
