#include "peer.h"
#include "guest.h"

#include <map>
#include <set>

#include <string.h>
#include <unistd.h>

char SHOST[DOMAINLIMIT];
uint16_t SPORT = 443;


struct Bindex{
    std::map<Guest* , std::set<Peer *>> left;
    std::map<Peer* , std::set<Guest *>> right;
    void insert(Guest* guest, Peer* peer);
    Peer *query(Peer *peer);
    void erase(Guest *guest, Peer *peer);
}bindex;

Peer::Peer(int fd):fd(fd) {
}

void Bindex::insert(Guest *guest, Peer *peer)
{
    if(!guest || !peer)
        return;
    if(left.count(guest)){
        left[guest].insert(peer);
    }else{
        std::set<Peer *> peers;
        peers.insert(peer);
        left.insert(std::make_pair(guest, peers));
    }
    
    if(right.count(peer)){
        right[peer].insert(guest);
    }else{
        std::set<Guest *> guests;
        guests.insert(guest);
        right.insert(std::make_pair(peer, guests));
    }
}

Peer * Bindex::query(Peer *peer){
    Guest *guest = static_cast<Guest *>(peer);
    if(left.count(guest)){
        return *left[guest].begin();
    }
    if(right.count(peer)){
        return *right[peer].begin();
    }
    return nullptr;
}

void Bindex::erase(Guest *guest, Peer *peer) {
    if(left.count(guest)){
        left[guest].erase(peer);
        if(left[guest].empty()){
            left.erase(guest);
        }
    }
    if(right.count(peer)){
        right[peer].erase(guest);
        if(right[peer].empty()){
            right.erase(peer);
        }
    }
}


Peer::~Peer() {
    if (fd > 0) {
        epoll_ctl(efd,EPOLL_CTL_DEL,fd,nullptr);
        close(fd);
    }
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
    return sizeof(wbuff)-writelen;
}


void connect(Guest* p1, Peer* p2) {
    bindex.insert(p1, p2);
}



Peer* queryconnect(Peer* key) {
    return bindex.query(key);
}

/*这里who为this，或者是NULL时都会disconnect所有连接的peer
 * 区别是who 为NULL时不会调用disconnect */
void Peer::disconnect(Peer* who, uint32_t errcode) {
    std::set<std::pair<Guest*, Peer*>> should_erase;
    Guest *this_is_guest= dynamic_cast<Guest *>(this);
    if(this_is_guest && bindex.left.count(this_is_guest)){
        std::set<Peer *> peers = bindex.left[this_is_guest];
        for(auto found: peers){
            if(who == this || who == nullptr || who == found) {
                should_erase.insert(std::make_pair(this_is_guest, found));
            }
        }
    }
    
    if(bindex.right.count(this)){
        std::set<Guest *> guests = bindex.right[this];
        for(auto found: guests){
            if(who == this || who == nullptr || who == found) {
                should_erase.insert(std::make_pair(found, this));
            }
        }
    }
    
    for(auto i: should_erase){
        bindex.erase(i.first, i.second);
    }
    
    if(who){
        if(this_is_guest){
            for(auto i: should_erase)
                i.second->clean(this_is_guest, errcode);
        }else{
            for(auto i: should_erase)
                i.first->clean(this, errcode);
        }
    }
}

void Peer::clean(Peer* who, uint32_t errcode) {
    disconnect(who, errcode);
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
