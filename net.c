#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "common.h"
#include "net.h"



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
    
    //以下设置为keealive配置，非必须，所以不检查返回值
    int keepAlive = 1; // 开启keepalive属性
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
    int idle = 60; //一分种没有交互就进行探测
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    int intvl = 10; //每10秒探测一次
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &intvl, sizeof(intvl));
    int cnt = 3; //探测3次无响应就关闭连接
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &cnt, sizeof(cnt));
    
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
