#include "simpleio.h"
#include "prot/dns.h"
#include "job.h"

#include <assert.h>

size_t RBuffer::left(){
    return sizeof(content) - len;
}

size_t RBuffer::length(){
    return len;
}

size_t RBuffer::add(size_t l){
    assert(len + l <= sizeof(content));
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


FdRWer::FdRWer(int fd, std::function<void(int ret, int code)> errorCB):RWer(errorCB, fd) {
    setEpoll(EPOLLIN);
    handleEvent = (void (Ep::*)(uint32_t))&FdRWer::defaultHE;
}

FdRWer::FdRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
            RWer(errorCB), port(port), protocol(protocol)
{
    strcpy(this->hostname, hostname);
    query(hostname, (DNSCBfunc)FdRWer::Dnscallback, this);
}

FdRWer::~FdRWer() {
    del_delayjob((job_func)con_timeout, this);
    query_cancel(hostname, (DNSCBfunc)FdRWer::Dnscallback, this);
}

void FdRWer::Dnscallback(FdRWer* rwer, const char* hostname, std::list<sockaddr_un> addrs) {
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
        rwer->handleEvent = (void (Ep::*)(uint32_t))&FdRWer::defaultHE;
        return;
    }
    rwer->connect();
}

void FdRWer::reconnect(int error) {
    if(!addrs.empty()){
        RcdDown(hostname, addrs.front());
        addrs.pop();
    }
    if(addrs.empty()){
        errorCB(error, 0);
        return;
    }
    connect();
}

void FdRWer::connect() {
    fd = Connect(&addrs.front(), (int)protocol);
    if (fd < 0) {
        LOGE("connect to %s failed\n", hostname);
        return reconnect(CONNECT_FAILED);
    }
    setEpoll(EPOLLOUT);
    handleEvent = (void (Ep::*)(uint32_t))&FdRWer::waitconnectHE;
    return add_delayjob((job_func)con_timeout, this, 30000);
}

int FdRWer::con_timeout(FdRWer* rwer) {
    close(rwer->fd);
    rwer->fd = -1;
    LOGE("connect to %s timeout\n", rwer->hostname);
    rwer->reconnect(CONNECT_TIMEOUT);
    return 0;
}


void FdRWer::waitconnectHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        Checksocket(fd);
        close(fd);
        fd = -1;
        return reconnect(CONNECT_FAILED);
    }
    if (events & EPOLLOUT) {
        setEpoll(EPOLLIN | EPOLLOUT);
        if(connectCB){
            connectCB();
        }
        handleEvent = (void (Ep::*)(uint32_t))&FdRWer::defaultHE;
        del_delayjob((job_func)con_timeout, this);
    }
}


void FdRWer::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, Checksocket(fd));
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
                break;
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
            int ret = wb.Write(std::bind(&FdRWer::Write, this, _1, _2));
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

ssize_t FdRWer::Read(void* buff, size_t len){
    return read(fd, buff, len);
}

ssize_t FdRWer::Write(const void* buff, size_t len){
    return write(fd, buff, len);
}

size_t FdRWer::rlength() {
    return rb.length();
}

const char* FdRWer::data(){
    return rb.start();
}

void FdRWer::consume(const char*, size_t l){
    rb.sub(l);
}



