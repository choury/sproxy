#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/epoll.h>



#include "peer.h"
#include "host.h"
#include "guest.h"
#include "common.h"

char SHOST[DOMAINLIMIT];
int SPORT=443;


Peerlist peerlist;



//这里初始化所有全局变量
Peerlist::Peerlist():list(){
    
}


void Peerlist::purge() {
    for (auto i = begin(); i != end();) {
        if ((*i)->candelete()) {
            delete *i;
            i=erase(i);
        } else {
            ++i;
        }
    }
}



Peer::Peer() {

}

Peer::Peer(int fd, int efd): fd(fd), efd(efd) {

};



Peer::~Peer() {
    if(fd) {
        close(fd);
    }
}

int Peer::Read(char* buff, size_t size) {
    return read(fd, buff, size);
}


int Peer::Write(const char* buff, size_t size) {

    int len = Min(size, bufleft());
    memcpy(wbuff + write_len, buff, len);
    write_len += len;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return len;
}

void Peer::peercanwrite() {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}


int Peer::Write() {
    int ret = write(fd, wbuff, write_len);

    if (ret < 0) {
        return ret;
    }

    if (ret == 0) {
        if (errno == 0)
            return 0;
        else
            return -1;
    }

    if (ret != write_len) {
        memmove(wbuff, wbuff + ret, write_len - ret);
        write_len -= ret;
    } else {
        write_len = 0;
    }

    return ret;
}

size_t Peer::bufleft() {
    if (sizeof(wbuff) == write_len)
        fulled = true;

    return sizeof(wbuff) - write_len;
}

/*
void connectHost(Host * host) {
    int hostfd = ConnectTo(host->hostname, host->targetport);

    pthread_mutex_lock(&lock);
    if(host->status == preconnect_s) {
        host->status=start_s;

        if (hostfd < 0) {
            fprintf(stderr, "connect to %s error\n", host->hostname);
            host->clean();
            pthread_mutex_unlock(&lock);
            return;
        }


        int flags = fcntl(hostfd, F_GETFL, 0);
        if (flags < 0) {
            perror("fcntl error");
            host->clean();
            pthread_mutex_unlock(&lock);
            return ;
        }
        fcntl(hostfd,F_SETFL,flags | O_NONBLOCK);


        host->fd = hostfd;
        host->guest->connected();

        struct epoll_event event;
        event.data.ptr = host;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(host->efd, EPOLL_CTL_ADD, host->fd, &event);
    } else {
        host->status=start_s;
        host->clean();
    }
    pthread_mutex_unlock(&lock);
}
*/