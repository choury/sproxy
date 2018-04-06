#include "simpleio.h"
#include "prot/dns.h"
#include "job.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

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

const char* RBuffer::data(){
    return content;
}

size_t RBuffer::consume(const char*, size_t l){
    assert(l <= len);
    len -= l;
    memmove(content, content+l, len);
    return l;
}

char* RBuffer::end(){
    return content+len;
}

size_t CBuffer::left(){
    uint32_t start = begin_pos % sizeof(content);
    uint32_t finish = end_pos % sizeof(content);
    if(finish > start || (finish == start && begin_pos == end_pos)){
        return sizeof(content) - finish;
    }else{
        return start - finish;
    }
}
size_t CBuffer::length(){
    assert(end_pos - begin_pos <= sizeof(content));
    return end_pos - begin_pos;
}
void CBuffer::add(size_t l){
    assert(l <= left());
    end_pos += l;
};
const char* CBuffer::data(){
    uint32_t start = begin_pos % sizeof(content);
    uint32_t finish = end_pos % sizeof(content);
    if(finish > start || (finish == start && begin_pos == end_pos)){
        return content + start;
    }else{
        char* buff = (char*)malloc(end_pos - begin_pos);
        size_t l = sizeof(content) - start;
        memcpy(buff, content + start, sizeof(content) - start);
        memcpy((char *)buff + l, content, finish);
        return  buff;
    }
}
void CBuffer::consume(const char* data, size_t l){
    begin_pos += l;
    assert(begin_pos <= end_pos);
    if(data < content || data >= content + sizeof(content)){
        free((char*)data);
    }
}

char* CBuffer::end(){
    return content + (end_pos % sizeof(content));
}

FdRWer::FdRWer(int fd, std::function<void(int ret, int code)> errorCB):RWer(errorCB, fd){
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
    del_delayjob((job_func)con_failed, this);
    query_cancel(hostname, (DNSCBfunc)FdRWer::Dnscallback, this);
}

void FdRWer::Dnscallback(FdRWer* rwer, const char*, std::list<sockaddr_un> addrs) {
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

void FdRWer::retryconnect(int error) {
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
        return add_postjob((job_func)con_failed, this);
    }
    setEpoll(EPOLLOUT);
    handleEvent = (void (Ep::*)(uint32_t))&FdRWer::waitconnectHE;
    return add_delayjob((job_func)con_failed, this, 30000);
}

int FdRWer::con_failed(FdRWer* rwer) {
    if(rwer->fd > 0){
        close(rwer->fd);
        rwer->fd = -1;
        LOGE("connect to %s timeout\n", rwer->hostname);
        rwer->retryconnect(CONNECT_TIMEOUT);
    }else{
        LOGE("connect to %s error\n", rwer->hostname);
        rwer->retryconnect(CONNECT_FAILED);
    }
    return 0;
}


void FdRWer::waitconnectHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        Checksocket(fd, __PRETTY_FUNCTION__);
        close(fd);
        fd = -1;
        return retryconnect(CONNECT_FAILED);
    }
    if (events & EPOLLOUT) {
        setEpoll(EPOLLIN | EPOLLOUT);
        if(connectCB){
            connectCB();
        }
        handleEvent = (void (Ep::*)(uint32_t))&FdRWer::defaultHE;
        del_delayjob((job_func)con_failed, this);
    }
}

ssize_t FdRWer::Write(const void* buff, size_t len){
    return write(fd, buff, len);
}

void FdRWer::Send(){
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
        return;
    }
    if(writed && writeCB){
        writeCB(writed);
    }
    if(wb.length() == 0){
        delEpoll(EPOLLOUT);
    }
}

/*

StreamRWer::StreamRWer(int fd, std::function<void (int, int)> errorCB):
            FdRWer(fd, errorCB)
{
}

StreamRWer::StreamRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void (int, int)> errorCB):
            FdRWer(hostname, port, protocol, errorCB)
{
}
*/

size_t StreamRWer::rlength() {
    return rb.length();
}

const char* StreamRWer::data(){
    return rb.data();
}

void StreamRWer::consume(const char* data, size_t l){
    rb.consume(data, l);
}

ssize_t StreamRWer::Read(void* buff, size_t len) {
    return read(fd, buff, len);
}

void StreamRWer::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, Checksocket(fd, __PRETTY_FUNCTION__));
        return;
    }
    if (events & EPOLLIN){
        bool closed = false;
        size_t left = 0;
        while((left = rb.left())){
            int ret = Read(rb.end(), left);
            if(ret > 0){
                rb.add(ret);
                continue;
            }
            if(ret == 0){
                delEpoll(EPOLLIN);
                closed = true;
                break;
            }
            if(errno == EAGAIN){
                break;
            }
            errorCB(READ_ERR, errno);
            return;
        }
        if(rb.length() && readCB){
            readCB(rb.length());
        }
        if(closed){
            errorCB(READ_ERR, 0);
        }
        if(rb.left() == 0){
            delEpoll(EPOLLIN);
        }
    }
    if (events & EPOLLOUT){
        Send();
    }
}

/*
PacketRWer::PacketRWer(int fd, std::function<void (int, int)> errorCB):
            FdRWer(fd, errorCB)
{
}

PacketRWer::PacketRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void (int, int)> errorCB):
            FdRWer(hostname, port, protocol, errorCB)
{
}

*/

size_t PacketRWer::rlength() {
    return rb.length();
}

const char* PacketRWer::data(){
    return rb.data();
}

void PacketRWer::consume(const char* data, size_t l){
    rb.consume(data, l);
}

ssize_t PacketRWer::Read(void* buff, size_t len) {
    return read(fd, buff, len);
}


void PacketRWer::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, Checksocket(fd, __PRETTY_FUNCTION__));
        return;
    }
    if (events & EPOLLIN){
        size_t left = 0;
        while((left = rb.left())){
            int ret = Read(rb.end(), left);
            if(ret > 0){
                rb.add(ret);
                if(readCB){
                    readCB(rb.length());
                }
                break; //break for do something else
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
            return;
        }
        if(rb.left() == 0){
            delEpoll(EPOLLIN);
        }
    }
    if (events & EPOLLOUT){
        Send();
    }
}
