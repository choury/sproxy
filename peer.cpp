#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>


#include "peer.h"
#include "host.h"
#include "guest.h"
#include "common.h"

char SHOST[DOMAINLIMIT];
uint16_t SPORT=1443;

Bindex bindex;

void Bindex::add(void* key1, void* key2) {
    map[key1]=key2;
    map[key2]=key1;
}


void Bindex::del(void* key1,void *key2) {
    map.erase(key1);
    map.erase(key2);
}

void Bindex::del(void* key){
    map.erase(key);
}

void* Bindex::query(void* key) {
    if(key && map.count(key)) {
        return map[key];
    } else {
        return nullptr;
    }
}



Peer::Peer() {

}

Peer::Peer(int fd): fd(fd) {

};



Peer::~Peer() {
    if(fd>0) {
        close(fd);
    }
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}


ssize_t Peer::Write(Peer *,const void* buff, size_t size) {

    int len = Min(size, bufleft());
    memcpy(wbuff + writelen, buff, len);
    writelen += len;

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
    if(epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    }
}


ssize_t Peer::Write() {
    ssize_t ret = write(fd, wbuff, writelen);

    if (ret < 0) {
        return ret;
    }

    if (ret == 0) {
        if (errno == 0)
            return 0;
        else
            return -1;
    }

    if ((size_t)ret != writelen) {
        memmove(wbuff, wbuff + ret, writelen - ret);
        writelen -= ret;
    } else {
        writelen = 0;
    }

    return ret;
}

size_t Peer::bufleft() {
    return sizeof(wbuff) - writelen;
}

void Peer::clean(Peer* who) {
    Peer *peer =(Peer *)bindex.query(this);
    bindex.del(this,peer);
    if(who==this && peer) {
        peer->clean(this);
    }

    if(fd!=0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        if(epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
        handleEvent=(void (Con::*)(uint32_t))&Peer::closeHE;
    } else {
        delete this;
    }
}

