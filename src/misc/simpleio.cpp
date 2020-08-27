#include "simpleio.h"
#include "prot/dns.h"
#include "misc/util.h"

#include <fcntl.h>
#include <sys/ioctl.h>
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

size_t RBuffer::consume(const char*, size_t l) {
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
        memcpy(buff + l, content, finish);
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

NetRWer::NetRWer(int fd, std::function<void(int ret, int code)> errorCB):RWer(fd, std::move(errorCB)){
    setEvents(RW_EVENT::READ);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&NetRWer::defaultHE;
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    socklen_t len = sizeof(addr);
    if(getpeername(fd, (sockaddr *)&addr, &len)){
        LOGE("getpeername error: %s\n", strerror(errno));
        return;
    }
    addrs.push(addr);
}

NetRWer::NetRWer(const char* hostname, uint16_t port, Protocol protocol,
               std::function<void(int ret, int code)> errorCB,
               std::function<void(const sockaddr_un&)> connectCB):
            RWer(std::move(errorCB), std::move(connectCB)), port(port), protocol(protocol)
{
    strcpy(this->hostname, hostname);
    stats = RWerStats::Dnsquerying;
    query(hostname, NetRWer::Dnscallback, this);
}

NetRWer::~NetRWer() {
    query_cancel(hostname, NetRWer::Dnscallback, this);
}

void NetRWer::Dnscallback(void* param, std::list<sockaddr_un> addrs) {
    NetRWer* rwer = static_cast<NetRWer*>(param);
    if (addrs.empty()) {
        rwer->stats = RWerStats::Error;
        return rwer->errorCB(DNS_FAILED, 0);
    }

    for(auto& i: addrs){
        i.addr_in6.sin6_port = htons(rwer->port);
        rwer->addrs.push(i);
    }
    switch(rwer->protocol){
    case Protocol::TCP:
    case Protocol::UDP:
        rwer->stats = RWerStats::Connecting;
        rwer->connect();
        break;
    case Protocol::ICMP: {
        int fd = IcmpSocket(&addrs.front());
        if (fd < 0) {
            rwer->stats = RWerStats::Error;
            return rwer->errorCB(CONNECT_FAILED, errno);
        }
        rwer->setFd(fd);
        rwer->setEvents(RW_EVENT::READWRITE);
        rwer->Connected(addrs.front());
        rwer->handleEvent = (void (Ep::*)(RW_EVENT)) &NetRWer::defaultHE;
        break;
    }
    default:
        abort();
    }
}

void NetRWer::retryconnect(int error) {
    setFd(-1);
    if(!addrs.empty()){
        RcdDown(hostname, addrs.front());
        addrs.pop();
    }
    if(addrs.empty()){
        stats = RWerStats::Error;
        errorCB(error, 0);
        return;
    }
    connect();
}

void NetRWer::connect() {
    int fd = Connect(&addrs.front(), (int)protocol);
    if (fd < 0) {
        con_failed_job = updatejob(con_failed_job, std::bind(&NetRWer::con_failed, this),  0);
        return;
    }
    setFd(fd);
    setEvents(RW_EVENT::WRITE);
    handleEvent = (void (Ep::*)(RW_EVENT))&NetRWer::waitconnectHE;
    con_failed_job = updatejob(con_failed_job, std::bind(&NetRWer::con_failed, this), 30000);
}

void NetRWer::con_failed() {
    if(getFd() >= 0){
        LOGE("connect to %s timeout\n", hostname);
        retryconnect(CONNECT_TIMEOUT);
    }else{
        LOGE("connect to %s error\n", hostname);
        retryconnect(CONNECT_FAILED);
    }
}


void NetRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR) || !!(events & RW_EVENT::READEOF)) {
        checkSocket(__PRETTY_FUNCTION__);
        return retryconnect(CONNECT_FAILED);
    }
    if (!!(events & RW_EVENT::WRITE)) {
        setEvents(RW_EVENT::READWRITE);
        Connected(addrs.front());
        handleEvent = (void (Ep::*)(RW_EVENT))&NetRWer::defaultHE;
        deljob(&con_failed_job);
    }
}

const char *NetRWer::getPeer() {
    if(addrs.empty()){
        return "net-rwer-null";
    }
    return getaddrportstring(&addrs.front());
}

const char *NetRWer::getDest(){
    static char buff[300];
    if(!hostname[0]){
        return "net-rwer-null";
    }
    sprintf(buff, "%s://%s:%d", protstr(protocol), hostname, port);
    return buff;
}

ssize_t NetRWer::Write(const void* buff, size_t len){
    return write(getFd(), buff, len);
}

size_t StreamRWer::rlength() {
    return rb.length();
}

size_t StreamRWer::rleft(){
    return rb.left();
}

const char* StreamRWer::rdata() {
    return rb.data();
}

void StreamRWer::consume(const char* data, size_t l) {
    rb.consume(data, l);
}

ssize_t StreamRWer::Read(void* buff, size_t len) {
    return read(getFd(), buff, len);
}

void StreamRWer::ReadData() {
    size_t left = 0;
    while((left = rb.left())){
        int ret = Read(rb.end(), left);
        if(ret > 0){
            rb.add((size_t)ret);
            continue;
        }
        if(ret == 0){
            stats = RWerStats::ReadEOF;
            break;
        }
        if(errno == EAGAIN){
            break;
        }
        stats = RWerStats::Error;
        errorCB(READ_ERR, errno);
        return;
    }
    if(rb.length()){
        readCB(rb.length());
    }
    if(rb.left() == 0){
        delEvents(RW_EVENT::READ);
    }
}

size_t PacketRWer::rlength() {
    return rb.length();
}

size_t PacketRWer::rleft(){
    return rb.left();
}

const char* PacketRWer::rdata() {
    return rb.data();
}

void PacketRWer::consume(const char* data, size_t l) {
    rb.consume(data, l);
}

ssize_t PacketRWer::Read(void* buff, size_t len) {
    return read(getFd(), buff, len);
}


void PacketRWer::ReadData() {
    size_t left = 0;
    while((left = rb.left())){
        int ret = Read(rb.end(), left);
        if(ret > 0){
            rb.add((size_t)ret);
            readCB(rb.length());
            continue;
        }
        if(ret == 0){
            stats = RWerStats::ReadEOF;
            break;
        }
        if(errno == EAGAIN){
            break;
        }
        stats = RWerStats::Error;
        errorCB(READ_ERR, errno);
        return;
    }
    if(rb.left() == 0){
        delEvents(RW_EVENT::READ);
    }
}


