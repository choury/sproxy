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
uint16_t SPORT=443;

Bindex bindex;

void Bindex::add(void* key1, void* key2){
    map[key1]=key2;
    map[key2]=key1;
}


void Bindex::del(void* key1,void *key2){
    map.erase(key1);
    map.erase(key2);
}


void* Bindex::query(void* key){
    if(key && map.count(key)){
        return map[key];
    }else{
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

int Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}


int Peer::Write(Peer *,const void* buff, size_t size) {

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

