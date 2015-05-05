#include <set>
#include <boost/bimap.hpp>  

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>


#include "peer.h"
#include "host.h"
#include "guest.h"

char SHOST[DOMAINLIMIT];
uint16_t SPORT = 443;

boost::bimap<Peer *,Peer *> bindex;


Peer::Peer(int fd):fd(fd) {
}



Peer::~Peer() {
    if (fd > 0) {
        epoll_ctl(efd,EPOLL_CTL_DEL,fd,nullptr);
        close(fd);
    }
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}


ssize_t Peer::Write(Peer *, const void* buff, size_t size) {
    int len = Min(size, bufleft());
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

size_t Peer::bufleft() {
    return sizeof(wbuff)-writelen < 100?0:sizeof(wbuff)-writelen;
}

/*
void Peer::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Peer read")) {
        clean(this);
    }
}
*/

void connect(Peer* p1, Peer* p2) {
    bindex.insert(boost::bimap<Peer *,Peer *>::value_type(p1,p2));
}



Peer* queryconnect(Peer* key) {
    if (bindex.left.count(key)){
        return bindex.left.find(key)->second;
    }
    if (bindex.right.count(key)) {
        return bindex.right.find(key)->second; 
    }
    return nullptr;
}


void Peer::disconnect(Peer* who) {
    if(bindex.left.count(this)){
        if(who == this || who == nullptr || who == bindex.left.find(this)->second){
            who = bindex.left.find(this)->second;
            bindex.left.erase(this);
            who->disconnected(this);
            
        }
    }
    if(bindex.right.count(this)){
        if(who == this || who == nullptr || who == bindex.right.find(this)->second){
            who = bindex.right.find(this)->second;
            bindex.right.erase(this);
            who->disconnected(this);
        }
    }
/*
    Peer *peer = queryconnect(this);
    bindex.left.erase(this);
    bindex.right.erase(this);
    if (who == this && peer) {
        if(tip){
            peer->Write(this, tip, strlen(tip));
        }
        peer->disconnect(this);
    }


    if (fd > 0) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
        handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
    } else if (who == this) {
        delete this;
    } */
}

void Peer::disconnected(Peer* who) {
    return clean();
}


void Peer::clean() {
    disconnect(nullptr);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLOUT;
    if (epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    }
    handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
}
