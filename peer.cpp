#include "peer.h"
#include "guest.h"
#include "binmap.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>

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
    while(!write_queue.empty()){
        free(write_queue.front().buff);
        write_queue.pop();
    }
}

ssize_t Peer::Write(const void* buff, size_t size, Peer* who, uint32_t id) {
    if(size == 0) {
        return 0;
    }
    void *dup_buff = malloc(size);
    memcpy(dup_buff, buff, size);
    return Write(dup_buff, size, who, id);
}

ssize_t Peer::Write(void* buff, size_t size, Peer* , uint32_t) {
    if(size == 0) {
        return 0;
    }
    
    write_block wb={buff, size, 0};
    write_queue.push(wb);
    writelen += size;

    if (fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    return size;
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}

ssize_t Peer::Write(const void* buff, size_t size) {
    return write(fd, buff, size);
}

int Peer::Write() {
    while(!write_queue.empty()){
        write_block *wb = &write_queue.front();
        ssize_t ret = Write((char *)wb->buff + wb->wlen, wb->len - wb->wlen);

        if (ret <= 0) {
            return ret;
        }

        writelen -= ret;
        if ((size_t)ret + wb->wlen == wb->len) {
            free(wb->buff);
            write_queue.pop();
        } else {
            wb->wlen += ret;
            return 1;
        }
    }

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return 2;
}

void Peer::writedcb(Peer *) {
    if (fd > 0 && !write_queue.empty()) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
    }
}

int32_t Peer::bufleft(Peer *) {
    if(writelen >= 1024*1024)
        return 0;
    else
        return 16384;
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

void Peer::clean(uint32_t errcode, Peer* who, uint32_t) {
    auto &&disconnected = disconnect(this, who);
    assert(!queryconnect(this));
    for(auto i: disconnected){
        if(i.first != who && i.first != this)
            i.first->clean(errcode, this);
        if(i.second != who && i.second != this)
            i.second->clean(errcode, this);
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

void Peer::closeHE(uint32_t events){
    if (write_queue.empty()){
        delete this;
        return;
    }

    int ret = Write();
    if (ret <= 0 && showerrinfo(ret, "write error while closing")) {
        delete this;
        return;
    }
}

void Peer::wait(Peer *who) {
    epoll_ctl(efd, EPOLL_CTL_DEL, who->fd, NULL);
}
