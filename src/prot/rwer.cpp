#include "rwer.h"
#include "common/common.h"
#include "misc/util.h"
#include "misc/net.h"

#include <unistd.h>
#include <assert.h>
#include <errno.h>

#ifdef __linux__
#include <sys/eventfd.h>
#endif

size_t RWer::wlength() {
    return wbuff.length();
}

std::list<write_block>::iterator WBuffer::start() {
    return write_queue.begin();
}

std::list<write_block>::iterator WBuffer::end() {
    return write_queue.end();
}

std::list<write_block>::iterator WBuffer::push(std::list<write_block>::insert_iterator i, const write_block& wb) {
    assert(wb.buff);
    len += wb.len;
    return write_queue.emplace(i, wb);
}

ssize_t WBuffer::Write(std::function<ssize_t(const void*, size_t)> write_func){
    auto wb = *write_queue.begin();
    write_queue.pop_front();
    assert(wb.buff);
    if(wb.len == 0){
        p_free(wb.buff);
        return Write(write_func);
    }
    assert(wb.offset < wb.len);
    ssize_t ret = write_func((const char *)wb.buff + wb.offset, wb.len - wb.offset);
    if (ret > 0) {
        assert(len >= (size_t)ret);
        len -= ret;
        assert(ret + wb.offset <= wb.len);
        if ((size_t)ret + wb.offset == wb.len) {
            p_free(wb.buff);
        } else {
            wb.offset += ret;
            write_queue.push_front(wb);
        }
    }else{
        write_queue.push_front(wb);
    }
    return ret;
}

size_t WBuffer::length() {
    return len;
}

/*
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
*/

WBuffer::~WBuffer() {
    while(!write_queue.empty()){
        p_free(write_queue.begin()->buff);
        write_queue.pop_front();
    }
    len = 0;
}

RWer::RWer(int fd, std::function<void(int ret, int code)> errorCB):
    Ep(fd), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    readCB = [this](size_t len){
        LOGE("discard data from stub readCB: %zd", len);
        consume(rdata(), len);
    };
    writeCB = [](size_t){};
}


RWer::RWer(std::function<void (int, int)> errorCB, std::function<void(const sockaddr_storage&)> connectCB):
           Ep(-1), connectCB(std::move(connectCB)), errorCB(std::move(errorCB))
{
    assert(this->errorCB != nullptr);
    assert(this->connectCB != nullptr);
    readCB = [this](size_t len){
        LOGE("discard data from stub readCB: %zd", len);
        consume(rdata(), len);
    };
    writeCB = [](size_t){};
}

void RWer::SendData(){
    size_t writed = 0;
    while(wbuff.length()){
        int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
        if(ret > 0){
            writed += ret;
            continue;
        }
        if(errno == EAGAIN){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(writed){
        writeCB(writed);
    }
    if(wbuff.length() == 0){
        delEvents(RW_EVENT::WRITE);
    }
}

void RWer::SetErrorCB(std::function<void(int ret, int code)> func){
    errorCB = std::move(func);
}

void RWer::SetReadCB(std::function<void(size_t len)> func){
    readCB = std::move(func);
    EatReadData();
}

void RWer::SetWriteCB(std::function<void(size_t len)> func){
    writeCB = std::move(func);
}

void RWer::defaultHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR) || stats == RWerStats::Error) {
        ErrorHE(SOCKET_ERR, checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ) || !!(events & RW_EVENT::READEOF)){
        flags |= RWER_READING;
        ReadData();
        flags &= ~RWER_READING;
    }
    if (!!(events & RW_EVENT::WRITE)){
        flags |= RWER_SENDING;
        SendData();
        flags &= ~RWER_SENDING;
    }
    if(stats == RWerStats::ReadEOF){
        delEvents(RW_EVENT::READ);
        if(rlength() == 0){
            errorCB(SOCKET_ERR, 0);
        }
    }
}

void RWer::closeHE(RW_EVENT) {
    if(wbuff.length() == 0){
        closeCB();
        return;
    }
    int ret = wbuff.Write(std::bind(&RWer::Write, this, _1, _2));
#ifndef WSL
    if ((wbuff.length() == 0) || (ret <= 0 && errno != EAGAIN)) {
        closeCB();
    }
#else
    if ((wbuff.length() == 0) || (ret <= 0)) {
        closeCB();
    }
#endif
}

bool RWer::supportReconnect(){
    return false;
}

void RWer::Reconnect() {
}

void RWer::Close(std::function<void()> func) {
    flags |= RWER_CLOSING;
    closeCB = std::move(func);
    if(getFd() >= 0 && stats != RWerStats::Connecting){
        setEvents(RW_EVENT::READWRITE);
        handleEvent = (void (Ep::*)(RW_EVENT))&RWer::closeHE;
    }else{
        closeCB();
    }
}

void RWer::EatReadData(){
    if(flags & RWER_READING){
        return;
    }
    switch(stats){
    case RWerStats::Connected:
        if(rlength()) {
            readCB(rlength());
        }
        addEvents(RW_EVENT::READ);
        break;
    case RWerStats::ReadEOF:
        if(rlength()){
            readCB(rlength());
        }else{
            errorCB(SOCKET_ERR, 0);
        }
        break;
    default:
        break;
    }
}

void RWer::Connected(const sockaddr_storage& addr){
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&RWer::defaultHE;
    connectCB(addr);
}

void RWer::ErrorHE (int ret, int code) {
    stats = RWerStats::Error;
    errorCB(ret, code);
}

void RWer::Shutdown() {
    stats = RWerStats::Shutdown;
    shutdown(getFd(), SHUT_WR);
}

std::list<write_block>::insert_iterator RWer::buffer_head() {
    return wbuff.start();
}

std::list<write_block>::insert_iterator RWer::buffer_end() {
    return wbuff.end();
}

std::list<write_block>::insert_iterator
RWer::buffer_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    assert(wb.offset <= wb.len);
    if(wb.offset < wb.len || wb.len == 0){
        addEvents(RW_EVENT::WRITE);
        return wbuff.push(where, wb);
    }else{
        p_free(wb.buff);
        return where;
    }
}

/*
void RWer::Clear(bool freebuffer) {
    wbuff.clear(freebuffer);
}
 */

NullRWer::NullRWer():RWer(-1, [](int, int){}) {
}

void NullRWer::consume(const char*, size_t) {
    LOGE("NullRWer consume was called\n");
    abort();
}

void NullRWer::ReadData() {
}

size_t NullRWer::rleft() {
    return 0;
}

size_t NullRWer::rlength() {
    return 0;
}

size_t NullRWer::wlength() {
    return 0;
}

ssize_t NullRWer::Write(const void*, size_t len) {
    LOG("discard everything write to NullRWer\n");
    return len;
}

const char * NullRWer::rdata() {
    return nullptr;
}

#ifdef __linux__
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB):
    RWer(errorCB, [](const sockaddr_storage&){})
{
    int evfd = eventfd(1, SOCK_CLOEXEC);
    if(evfd < 0){
        stats = RWerStats::Error;
        errorCB(SOCKET_ERR, errno);
        return;
    }
    setFd(evfd);
    write(evfd, "FULLEVENT", 8);
#else
FullRWer::FullRWer(std::function<void(int ret, int code)> errorCB):
    RWer(errorCB, [](const sockaddr_storage&){}), pairfd(-1){
    int pairs[2];
    int ret = socketpair(AF_UNIX, SOCK_STREAM, 0, pairs);
    if(ret){
        stats = RWerStats::Error;
        errorCB(SOCKET_ERR, errno);
        return;
    }
    setFd(pairs[0]);
    // pairfd should set noblock manually
    pairfd = pairs[1];
    SetSocketUnblock(pairfd);
    write(pairfd, "FULLEVENT", 8);
#endif
    setEvents(RW_EVENT::READ);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&FullRWer::defaultHE;
}

FullRWer::~FullRWer(){
#ifndef __linux__
    if(pairfd >= 0){
        close(pairfd);
    }
#endif
}

ssize_t FullRWer::Write(const void* buff, size_t len) {
#ifdef __linux__
    return write(getFd(), buff, len);
#else
    return write(pairfd, buff, len);
#endif
}

size_t FullRWer::rlength() {
    return 0;
}

size_t FullRWer::rleft(){
    return 0;
}

const char* FullRWer::rdata() {
    return nullptr;
}

void FullRWer::consume(const char*, size_t) {
}


void FullRWer::ReadData(){
    while(!!(events & RW_EVENT::READ)) {
        readCB(1);
    }
    Write("FULLEVENT", 8);
}

void FullRWer::closeHE(RW_EVENT) {
    closeCB();
}

