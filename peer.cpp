#include "peer.h"
#include "guest.h"

#include <boost/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>

#include <string.h>

char SHOST[DOMAINLIMIT];
uint16_t SPORT = 3334;

boost::bimap<boost::bimaps::multiset_of<Guest *>,boost::bimaps::multiset_of<Peer *>> bindex;

Peer::Peer(int fd):fd(fd) {
}



Peer::~Peer() {
//    disconnect(this);
    if (fd > 0) {
        epoll_ctl(efd,EPOLL_CTL_DEL,fd,nullptr);
        close(fd);
    }
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
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

void Peer::writedcb() {
    if (fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
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

size_t Peer::bufleft(Peer *) {
    return sizeof(wbuff)-writelen < 100?0:sizeof(wbuff)-writelen;
}

/*
void Peer::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Peer read")) {
        clean(this);
    }
}
*/

void connect(Guest* p1, Peer* p2) {
    auto range = bindex.left.equal_range(p1);
    for(auto i=range.first;i!=range.second;i++)
        if(p2 == i->second)
            return;
    bindex.insert(decltype(bindex)::value_type(p1,p2));
}



Peer* queryconnect(Peer* key) {
    Guest *guest = dynamic_cast<Guest *>(key);
    if (guest){
        if (bindex.left.count(guest)){
            return bindex.left.find(guest)->second;
        }
        return nullptr;
    }else{
        if (bindex.right.count(key)) {
            return bindex.right.find(key)->second; 
        }
        return nullptr;
    }
}

/*这里who为this，或者是NULL时都会disconnect所有连接的peer
 * 区别是who 为NULL时不会调用disconnect */
void Peer::disconnect(Peer* who, uint32_t errcode) {
    Guest *this_is_guest= dynamic_cast<Guest *>(this);
    if(this_is_guest){
        auto range = bindex.left.equal_range(this_is_guest);
        for(auto i=range.first;i!=range.second;){
            Peer *found = i->second;
            if(who == this || who == nullptr || who == found) {
                bindex.left.erase(i++);
            }else{
                i++;
            }
            if(who) {
                found->disconnected(this, errcode);
            }
        }
        return;
    }
    
    auto range = bindex.right.equal_range(this);
    for(auto i=range.first;i!=range.second;){
        Guest *found = i->second;
        if(who == this || who == nullptr || who == found) {
            bindex.right.erase(i++);
        }else{
            i++;
        }
        if(who) {
            found->disconnected(this, errcode);
        }
    }
}

void Peer::disconnected(Peer* who, uint32_t errcode) {
    return clean(who, errcode);
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
