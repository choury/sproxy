#include "peer.h"
#include "guest.h"
#include "binmap.h"

#include <string.h>
#include <unistd.h>

char SHOST[DOMAINLIMIT];
uint16_t SPORT = 443;
uint16_t CPORT = 3333;

class binmap<Guest *, Peer*> bindex;

Peer::Peer(int fd):fd(fd) {
}


Peer::~Peer() {
    if (fd > 0) {
        epoll_ctl(efd,EPOLL_CTL_DEL,fd,nullptr);
        close(fd);
    }
    assert(!queryconnect(this));
}

ssize_t Peer::Write(Peer* who, const void* buff, size_t size) {
    int len = Min(size, bufleft(who));
    memcpy(wbuff + writelen, buff, len);
    writelen += len;

    if (fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    return len;
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}

ssize_t Peer::Write(const void* buff, size_t size) {
    return write(fd, buff, size);
}

ssize_t Peer::Write() {
    ssize_t ret = Write(wbuff, writelen);

    if (ret <= 0) {
        return ret;
    }

    if ((size_t)ret != writelen) {
        memmove(wbuff, wbuff + ret, writelen - ret);
        writelen -= ret;
    } else {
        writelen = 0;
    }

    return ret;
}

void Peer::writedcb(Peer *) {
    if (fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
    }
}

int32_t Peer::bufleft(Peer *) {
    return sizeof(wbuff)-writelen - 20; //reserved 20 bytes for chunked(ffffffffffffffff\r\n.....\r\n)
}


void connect(Guest* p1, Peer* p2) {
    bindex.insert(p1, p2);
}


Guest* queryconnect(Peer * key) {
    try{
        return bindex.at(key);
    }catch(...){
        return nullptr;
    }
}

Peer* queryconnect(Guest * key) {
    try{
        return bindex.at(key);
    }catch(...){
        return nullptr;
    }
}

/*这里who为this，会disconnect所有连接的peer */
std::set<std::pair<Guest *, Peer *>> disconnect(Peer *k1, Peer* k2) {
    std::set<std::pair<Guest*, Peer*>> should_erase;
    Guest *k1_is_guest= dynamic_cast<Guest *>(k1);
    if(k1_is_guest && bindex.count(k1_is_guest)){
        assert(k1 == k2 || !dynamic_cast<Guest *>(k2));
        std::set<Peer *> peers = bindex[k1_is_guest];
        for(auto found: peers){
            if(k2 == k1 || k2 == found) {
                should_erase.insert(std::make_pair(k1_is_guest, found));
            }
        }
    }
    
    if(bindex.count(k1)){
        assert(!k1_is_guest);
        std::set<Guest *> guests = bindex[k1];
        for(auto found: guests){
            if(k2 == k1 || k2 == found) {
                should_erase.insert(std::make_pair(found, k1));
            }
        }
    }
    
    for(auto i: should_erase){
        bindex.erase(i.first, i.second);
    }
    return should_erase;
}

void Peer::clean(Peer* who, uint32_t errcode) {
    auto &&disconnected = disconnect(this, who);
    assert(!queryconnect(this));
    for(auto i: disconnected){
        if(i.first != who && i.first != this)
            i.first->clean(this, errcode);
        if(i.second != who && i.second != this)
            i.second->clean(this, errcode);
    }
    if(fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
        handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
    }
}

void Peer::wait(Peer *who) {
    epoll_ctl(efd, EPOLL_CTL_DEL, who->fd, NULL);
}

int Peer::showstatus(Peer *who, char *buff) {
    strcpy(buff, "\r\n");
    return 2;
}
