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
uint16_t SPORT=443;

Peer::Peer() {

}

Peer::Peer(int fd, int efd): fd(fd), efd(efd) {

};



Peer::~Peer() {
    if(fd>0) {
        close(fd);
    }
}

int Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}


int Peer::Write(const void* buff, size_t size) {

    int len = Min(size, bufleft());
    memcpy(wbuff + write_len, buff, len);
    write_len += len;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return len;
}

void Peer::writedcb() {
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
    return sizeof(wbuff) - write_len;
}


void Peer::closeHE(uint32_t events){
    if (events & EPOLLOUT) {
        if(write_len == 0) {
            delete this;
            return;
        }

        int ret = Write();

        if (ret <= 0 && showerrinfo(ret,"write error while closing")) {
            delete this;
            return;
        }
    }
}
