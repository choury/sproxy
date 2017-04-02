#include "base.h"

#include <set>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#ifndef NDEBUG
#include <map>
#include "common.h"
static  std::map<int, Con *> epolls;
static const char *epoll_string[]= {
    "NULL",
    "EPOLLIN",
    "EPOLLPRI",
    "EPOLLIN|EPOLLPRI",
    "EPOLLOUT",
    "EPOLLOUT|EPOLLIN",
    "EPOLLOUT|EPOLLPRI",
    "EPOLLOUT|EPOLLIN|EPOLLPRI",
};
#endif

extern int efd;

static std::set<Con*> cons;

Con::Con(int fd):fd(fd){
    cons.insert(this);
}

Con::~Con(){
    if(fd > 0){
        int __attribute__((unused)) ret = close(fd);
        assert(ret == 0 || fprintf(stderr, "close error:%m\n") == 0);
    }
    cons.erase(this);
}

void Con::updateEpoll(uint32_t events) {
    int __attribute__((unused)) ret;
    if (fd > 0) {
        if(events == 0){
#ifndef NDEBUG
            LOGD(DEPOLL, "del %d: %p\n", fd, this);
            assert(epolls[fd] == this);
            epolls.erase(fd);
#endif
            ret =  epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
            assert(ret == 0 || fprintf(stderr, "epoll_ctl del failed:%m\n"));
        }else{
            struct epoll_event event;
            event.data.ptr = this;
            event.events = events;
            ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            assert(ret == 0 || errno == ENOENT || fprintf(stderr, "epoll_ctl mod failed:%m\n")==0);
            if (ret && errno == ENOENT)
            {
                ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
                assert(ret == 0 || fprintf(stderr, "epoll_ctl add failed:%m\n")==0);
#ifndef NDEBUG
                LOGD(DEPOLL, "add %d: %p\n", fd, this);
                epolls[fd]=this;
#endif
            }else{
#ifndef NDEBUG
                if(epolls[fd] != this) {
                    LOGD(DEPOLL, "change %d: %p --> %p\n", fd, epolls[fd], this);
                }
                assert(epolls.count(fd));
                epolls[fd]=this;
#endif
            }
#ifndef NDEBUG
            if(events != this->events) {
                assert(events <= 7);
                LOGD(DEPOLL, "modify %d: %s --> %s\n", fd, epoll_string[this->events], epoll_string[events]);
            }
#endif
            this->events = events;
        }
    }
}
void Con::discard(){
    fd = 0;
    events = 0;
}

Server::Server(int fd):Con(fd){
    updateEpoll(EPOLLIN);
    handleEvent = (void (Con::*)(uint32_t))&Server::defaultHE;
}



Peer::Peer(int fd):Con(fd) {
}


Peer::~Peer() {
    while(!write_queue.empty()){
        p_free(write_queue.front().buff);
        write_queue.pop();
    }
}

ssize_t Peer::push_buff(void* buff, size_t size) {
    if(size == 0) {
        p_free(buff);
        return 0;
    }
    write_block wb={buff, size, 0};
    write_queue.push(wb);
    writelen += size;

    updateEpoll(events | EPOLLOUT);
    return size;
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}

ssize_t Peer::Write(const void* buff, size_t size) {
    return write(fd, buff, size);
}

int Peer::Write_buff() {
    bool writed = false;
    while(!write_queue.empty()){
        write_block *wb = &write_queue.front();
        ssize_t ret = Write((char *)wb->buff + wb->wlen, wb->len - wb->wlen);

        if (ret <= 0) {
            return ret;
        }

        writed = true;
        writelen -= ret;
        assert(ret + wb->wlen <= wb->len);
        if ((size_t)ret + wb->wlen == wb->len) {
            p_free(wb->buff);
            write_queue.pop();
        } else {
            wb->wlen += ret;
            return WRITE_INCOMP;
        }
    }

    updateEpoll(EPOLLIN);
    return writed ? WRITE_COMPLETE : WRITE_NOTHING;
}


ssize_t Peer::Write(const void* buff, size_t size, void* index) {
    return Write(p_memdup(buff, size), size, index);
}

ssize_t Peer::Write(void* buff, size_t size, void*) {
    return push_buff(buff, size);
}

void Peer::wait(void*){

}

void Peer::writedcb(void*) {
    updateEpoll(events | EPOLLIN);
}

int32_t Peer::bufleft(void*) {
    if(writelen >= 1024*1024)
        return 0;
    else
        return BUF_LEN;
}



void Peer::clean(uint32_t errcode, void*) {
    if(fd > 0) {
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
    }else{
        delete this;
    }
}


void releaseall() {
    auto cons_copy = cons;
    for(auto i:cons_copy){
        delete i;
    }
    close(efd);
}

extern void flushproxy2();

int setproxy(const char* proxy){
    char protocol[DOMAINLIMIT];
    char shost[DOMAINLIMIT];
    uint16_t sport;
    if(spliturl(proxy, protocol, shost, nullptr, &sport)){
        return -1;
    }

    if(strlen(protocol) == 0 ||
        strcasecmp(protocol, "ssl") == 0)
    {
        SPROT = Protocol::TCP;
    }else if(strcasecmp(protocol, "dtls") == 0){
        SPROT = Protocol::UDP;
    }else{
        return -1;
    }
    if(sport == 0){
        SPORT = 443;
    }else{
        SPORT = sport;
    }
    strcpy(SHOST, shost);
    flushproxy2();
    return 0;
}

int getproxy(char *buff, size_t buflen){
    switch(SPROT){
    case Protocol::TCP:
        return snprintf(buff, buflen, "ssl://%s:%d", SHOST, SPORT)+1;
    case Protocol::UDP:
        return snprintf(buff, buflen, "dtls://%s:%d", SHOST, SPORT)+1;
    }
}
