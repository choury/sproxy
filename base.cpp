#include "base.h"
#include "misc/util.h"
#include "misc/job.h"
#include "prot/dns.h"

#include <set>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

static std::set<Server*> servers;

Server::Server(){
    servers.insert(this);
}

Server::~Server(){
    delete rwer;
    servers.erase(this);
}

void Peer::deleteLater(uint32_t errcode) {
    rwer->Close([this](){
        delete this;
    });
}

ssize_t Peer::Send(const void* buff, size_t size, void* index) {
    return Send(p_memdup(buff, size), size, index);
}

void Peer::writedcb(void*) {
    rwer->addEpoll(EPOLLIN);
    rwer->TrigRead();
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



size_t RBuffer::left(){
    return BUF_LEN - len;
}

size_t RBuffer::length(){
    return len;
}

size_t RBuffer::add(size_t l){
    assert(len + l <= BUF_LEN);
    len += l;
    return l;
}

size_t RBuffer::sub(size_t l){
    assert(l <= len);
    len -= l;
    memmove(content, content+l, len);
    return l;
}

char* RBuffer::start(){
    return content;
}

char* RBuffer::end(){
    return content+len;
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
    write_block wb={buff, size, 0};
    len += size;
    return write_queue.insert(i, wb);
}



ssize_t  WBuffer::Write(std::function<ssize_t(const void*, size_t)> write_func){
    write_block& wb = write_queue.front();
    ssize_t ret = write_func((char *)wb.buff + wb.wlen, wb.len - wb.wlen);
    if (ret > 0) {
        len -= ret;
        assert(ret + wb.wlen <= wb.len);
        if ((size_t)ret + wb.wlen == wb.len) {
            p_free(wb.buff);
            write_queue.pop_front();
        } else {
            wb.wlen += ret;
        }
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

WBuffer::~WBuffer() {
    while(!write_queue.empty()){
        p_free(write_queue.front().buff);
        write_queue.pop_front();
    }
}


RWer::RWer(int fd, std::function<void(int ret, int code)> errorCB):Ep(fd), errorCB(errorCB) {
    setEpoll(EPOLLIN);
    handleEvent = (void (Ep::*)(uint32_t))&RWer::defaultHE;
}

RWer::RWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
            Ep(0), port(port), protocol(protocol), errorCB(errorCB)
{
    query(hostname, (DNSCBfunc)RWer::Dnscallback, this);
}

void RWer::Dnscallback(RWer* rwer, const char* hostname, std::list<sockaddr_un> addrs) {
    if(rwer->closeCB){
        return rwer->closeCB();
    }
    strcpy(rwer->hostname, hostname);
    if (addrs.empty()) {
        return rwer->errorCB(DNS_FAILED, 0);
    }

    for(auto& i: addrs){
        i.addr_in6.sin6_port = htons(rwer->port);
        rwer->addrs.push(i);
    }
    if(rwer->protocol == Protocol::ICMP){
        rwer->fd = IcmpSocket(&addrs.front(), rwer->port);
        if(rwer->fd < 0){
            return rwer->errorCB(CONNECT_FAILED, errno);
        }
        rwer->setEpoll(EPOLLIN | EPOLLOUT);
        if(rwer->connectCB){
            rwer->connectCB();
        }
        rwer->handleEvent = (void (Ep::*)(uint32_t))&RWer::defaultHE;
        return;
    }
    rwer->connect();
}

void RWer::reconnect(int error) {
    if(!addrs.empty()){
        RcdDown(hostname, addrs.front());
        addrs.pop();
    }
    if(addrs.empty()){
        del_delayjob((job_func)con_timeout, this);
        errorCB(error, 0);
        return;
    }
    connect();
}

void RWer::connect() {
    fd = Connect(&addrs.front(), (int)protocol);
    if (fd < 0) {
        LOGE("connect to %s failed\n", hostname);
        return reconnect(CONNECT_FAILED);
    }
    setEpoll(EPOLLOUT);
    handleEvent = (void (Ep::*)(uint32_t))&RWer::waitconnectHE;
    return add_delayjob((job_func)con_timeout, this, 30000);
}

int RWer::checksocket(){
    int       error = 0;
    socklen_t errlen = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) != 0) {
        error = errno;
        LOGE("getsockopt error: %s\n", strerror(error));
    }else if(error){
        LOGE("sock error: %s\n", strerror(error));
    }
    return error;
}

int RWer::con_timeout(RWer* rwer) {
    close(rwer->fd);
    LOGE("connect to %s timeout\n", rwer->hostname);
    rwer->reconnect(CONNECT_TIMEOUT);
    return 0;
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = func;
}

void RWer::SetReadCB(std::function<void(size_t len)> func){
    readCB = func;
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
    writeCB = func;
}

void RWer::SetConnectCB(std::function<void()> func){
    connectCB = func;
}

#if 0
ssize_t RWer::push_back(const void* buff, size_t len) {
    return push_back(p_memdup(buff, len), len);
}

ssize_t RWer::push_back(void* buff, size_t len){
    addEpoll(EPOLLOUT);
    wb.push_back(buff, len);
    return len;
}

ssize_t RWer::push_front(const void* buff, size_t len) {
    return push_front(p_memdup(buff, len), len);
}

ssize_t RWer::push_front(void* buff, size_t len) {
    addEpoll(EPOLLOUT);
    wb.push_front(buff, len);
    return len;
}
#endif

void RWer::waitconnectHE(int events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        checksocket();
        close(fd);
        return reconnect(CONNECT_FAILED);
    }
    if (events & EPOLLOUT) {
        setEpoll(EPOLLIN | EPOLLOUT);
        if(connectCB){
            connectCB();
        }
        handleEvent = (void (Ep::*)(uint32_t))&RWer::defaultHE;
        del_delayjob((job_func)con_timeout, this);
    }
}


void RWer::defaultHE(int events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, checksocket());
        return;
    }
    if (events & EPOLLIN){
        while(rb.left()){
            int ret = Read(rb.end(), rb.left());
            if(ret > 0){
                rb.add(ret);
                if(readCB){
                    readCB(rb.length());
                }
                continue;
            }
            if(ret == 0){
                delEpoll(EPOLLIN);
                errorCB(READ_ERR, 0);
                break;
            }
            if(errno == EAGAIN){
                break;
            }
            errorCB(READ_ERR, errno);
            break;
        }
        if(rb.left()==0){
            delEpoll(EPOLLIN);
        }
    }
    if (events & EPOLLOUT){
        size_t writed = 0;
        while(wb.length()){
            int ret = wb.Write(std::bind(&RWer::Write, this, _1, _2));
            assert(ret != 0);
            if(ret > 0){
                writed += ret;
                continue;
            }
            if(errno == EAGAIN){
                break;
            }
            errorCB(WRITE_ERR, errno);
            break;
        }
        if(wb.length() == 0){
            delEpoll(EPOLLOUT);
        }
        if(writed && writeCB){
            writeCB(writed);
        }
    }
}

void RWer::closeHE(int events) {
    int ret = wb.Write(std::bind(&RWer::Write, this, _1, _2));
    if ((wb.length() == 0) || (ret <= 0 && errno != EAGAIN)) {
        closeCB();
        return;
    }
}


ssize_t RWer::Read(void* buff, size_t len){
    return read(fd, buff, len);
}

ssize_t RWer::Write(const void* buff, size_t len){
    return write(fd, buff, len);
}

void RWer::TrigRead(){
    if(rb.length() && readCB){
        readCB(rb.length());
    }
}

void RWer::Close(std::function<void()> func) {
    closeCB = func;
    if(fd > 0){
        setEpoll(EPOLLOUT);
        handleEvent = (void (Ep::*)(uint32_t))&RWer::closeHE;
    }else if(hostname[0]){
        closeCB();
    }
}

void RWer::Shutdown() {
    shutdown(fd, SHUT_WR);
}

size_t RWer::wlength() {
    return wb.length();
}

size_t RWer::rlength() {
    return rb.length();
}

const char* RWer::data(){
    return rb.start();
}

void RWer::consume(size_t l){
    rb.sub(l);
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

extern void dump_dns();
extern void dump_job();

void dump_stat(int){
    LOG("======================================\n");
    char buff[DOMAINLIMIT];
    getproxy(buff, sizeof(buff));
    LOG("Proxy server: %s\n", buff);
    LOG("--------------------------------------\n");
    for(auto i: servers){
        i->dump_stat();
        LOG("--------------------------------------\n");
    }
    dump_dns();
    LOG("--------------------------------------\n");
    dump_job();
    LOG("======================================\n");
}

int setproxy(const char* proxy){
    if(spliturl(proxy, SPROT, SHOST, nullptr, &SPORT)){
        return -1;
    }

    if(SPORT == 0){
        SPORT = 443;
    }
    //TODO
    //flushproxy2();
    return 0;
}

int getproxy(char *buff, size_t buflen){
    return snprintf(buff, buflen, "%s://%s:%d", SPROT, SHOST, SPORT)+1;
}
