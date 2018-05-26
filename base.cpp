#include "base.h"
#include "misc/util.h"
#include "misc/job.h"
#include "prot/dns.h"

#include <set>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>

static std::set<Server*> servers;

Server::Server(){
    servers.insert(this);
}

Server::~Server(){
    delete rwer;
    servers.erase(this);
}

void Peer::deleteLater(uint32_t) {
    if(rwer){
        rwer->Close([this](){
            delete this;
        });
    }else{
        delete this;
    }
}

ssize_t Peer::Send(const void* buff, size_t size, void* index) {
    return Send(p_memdup(buff, size), size, index);
}

void Peer::writedcb(void*) {
    if(rwer){
        rwer->addEpoll(EPOLLIN);
        rwer->TrigRead();
    }
}


#ifndef NDEBUG
#include <map>
static  std::map<int, Ep *> epolls;
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

Ep::Ep(int fd):fd(fd){

}

Ep::~Ep(){
    if(fd > 0){
        if(close(fd) != 0){
            LOGE("close error:%s\n", strerror(errno));
        }
    }
}

void Ep::setEpoll(uint32_t events) {
    if(events == this->events){
        return;
    }
    if (fd > 0) {
        int __attribute__((unused)) ret;
        struct epoll_event event;
        event.data.ptr = this;
        event.events = events | EPOLLHUP | EPOLLERR;
        ret = epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        if(ret != 0 && errno != ENOENT){
            LOGE("epoll_ctl mod failed:%s\n", strerror(errno));
        }
        if (ret && errno == ENOENT)
        {
            ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
            if(ret != 0){
                LOGE("epoll_ctl add failed:%s\n", strerror(errno));
            }
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

void Ep::addEpoll(uint32_t events){
    return setEpoll(this->events | events);
}

void Ep::delEpoll(uint32_t events){
    return setEpoll(this->events & ~events);
}


size_t RWer::wlength() {
    return wb.length();
}

std::list<write_block>::iterator WBuffer::start() {
    return write_queue.begin();
}

std::list<write_block>::iterator WBuffer::end() {
    return write_queue.end();
}

std::list<write_block>::iterator WBuffer::push(std::list<write_block>::insert_iterator i, void* buff, size_t size) {
    if(size == 0) {
        p_free(buff);
        return write_queue.erase(i, i);
    }
    assert(buff);
    write_block wb={buff, size, 0};
    len += size;
    return write_queue.insert(i, wb);
}

ssize_t  WBuffer::Write(std::function<ssize_t(const void*, size_t)> write_func){
    auto i = write_queue.begin();
    assert(i->buff);
    assert(i->wlen < i->len);
    ssize_t ret = write_func((char *)i->buff + i->wlen, i->len - i->wlen);
    if (ret > 0) {
        len -= ret;
        assert(ret + i->wlen <= i->len);
        if ((size_t)ret + i->wlen == i->len) {
            p_free(i->buff);
            write_queue.pop_front();
        } else {
            i->wlen += ret;
        }
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

void WBuffer::clear(bool freebuffer){
    if(freebuffer){
        while(!write_queue.empty()){
            p_free(write_queue.begin()->buff);
            write_queue.pop_front();
        }
    }else{
        write_queue.clear();
    }
    len = 0;
}

WBuffer::~WBuffer() {
    clear(true);
}

RWer::RWer(std::function<void (int, int)> errorCB, int fd):Ep(fd), errorCB(errorCB) {
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = func;
}

void RWer::SetReadCB(std::function<void(size_t len)> func){
    readCB = func;
    TrigRead();
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
    writeCB = func;
}

void RWer::SetConnectCB(std::function<void()> func){
    connectCB = func;
}

void RWer::closeHE(uint32_t) {
    if(wb.length() == 0){
        closeCB();
        return;
    }
    int ret = wb.Write(std::bind(&RWer::Write, this, _1, _2));
    if ((wb.length() == 0) || (ret <= 0 && errno != EAGAIN)) {
        closeCB();
        return;
    }
}

bool RWer::supportReconnect(){
    return false;
}

void RWer::Reconnect() {
}


void RWer::TrigRead(){
    if(rlength() && readCB){
        readCB(rlength());
    }
}

void RWer::Close(std::function<void()> func) {
    closeCB = func;
    if(fd > 0){
        setEpoll(EPOLLOUT);
        handleEvent = (void (Ep::*)(uint32_t))&RWer::closeHE;
    }else{
        closeCB();
    }
}

void RWer::Shutdown() {
    shutdown(fd, SHUT_WR);
}

std::list<write_block>::insert_iterator RWer::buffer_head() {
    return wb.start();
}

std::list<write_block>::insert_iterator RWer::buffer_end() {
    return wb.end();
}

ssize_t RWer::buffer_insert(std::list<write_block>::insert_iterator where, const void* buff, size_t len) {
    return buffer_insert(where, p_memdup(buff, len), len);
}

ssize_t RWer::buffer_insert(std::list<write_block>::insert_iterator where, void* buff, size_t len) {
    addEpoll(EPOLLOUT);
    wb.push(where, buff, len);
    return len;
}

void RWer::Clear(bool freebuffer) {
    wb.clear(freebuffer);
}

void releaseall() {
    auto cons_copy = servers;
    for(auto i:cons_copy){
        delete i;
    }
    if(efd){
        close(efd);
        efd = 0;
    }
}

extern void dump_dns(Dumper dp, void* param);
extern void dump_job(Dumper dp, void* param);

void dump_stat(Dumper dp, void* param){
    dp(param, "======================================\n");
    char buff[DOMAINLIMIT];
    getproxy(buff, sizeof(buff));
    dp(param, "Proxy server: %s\n", buff);
    dp(param, "--------------------------------------\n");
    for(auto i: servers){
        i->dump_stat(dp, param);
        dp(param, "--------------------------------------\n");
    }
    dump_dns(dp, param);
    dp(param, "--------------------------------------\n");
    dump_job(dp, param);
    dp(param, "======================================\n");
}

static void LogDump(void*, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    VLOG(LOG_INFO, fmt, ap);
    va_end(ap);
}

void dump_stat(int sig){
    dump_stat(LogDump, nullptr);
    if(sig == SIGSEGV){
        exit(-1);
    }
}

int setproxy(const char* proxy){
    if(spliturl(proxy, SPROT, SHOST, nullptr, &SPORT)){
        return -1;
    }

    if(SPORT == 0){
        SPORT = 443;
    }
    flushproxy2(true);
    return 0;
}

int getproxy(char *buff, size_t buflen){
    if(SHOST[0] == 0) {
        buff[0] = 0;
        return 0;
    }else{
        if(SPROT[0]){
            return snprintf(buff, buflen, "%s://%s:%d", SPROT, SHOST, SPORT)+1;
        }else{
            return snprintf(buff, buflen, "%s:%d", SHOST, SPORT)+1;
        }
    }
}
