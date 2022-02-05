#include "netio.h"
#include "dns/resolver.h"
#include "misc/util.h"
#include "misc/net.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#if __APPLE__
#include <sys/ucred.h>
#include <sys/un.h>
#endif

size_t RBuffer::left(){
    return sizeof(content) - len;
}

size_t RBuffer::length(){
    assert(len <= sizeof(content));
    return len;
}

size_t RBuffer::add(size_t l){
    assert(len + l <= sizeof(content));
    len += l;
    return l;
}

ssize_t RBuffer::put(const void *data, size_t size) {
    if(len + size > sizeof(content)){
        return -1;
    }
    memcpy(content + len, data, size);
    len += size;
    return (ssize_t)len;
}

size_t RBuffer::cap() {
    return sizeof(content) - len;
}

const char* RBuffer::data(){
    return content;
}

size_t RBuffer::consume(size_t l) {
    assert(l <= len);
    len -= l;
    memmove(content, content+l, len);
    return l;
}

char* RBuffer::end(){
    return content+len;
}

size_t CBuffer::left(){
    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + len) % sizeof(content);
    if(finish > start || len == 0){
        return sizeof(content) - finish;
    }else{
        return start - finish;
    }
}

size_t CBuffer::length(){
    assert(len <= sizeof(content));
    return len;
}

size_t CBuffer::cap() {
    return sizeof(content) - len;
}

void CBuffer::add(size_t l){
    len += l;
    assert(len <= sizeof(content));
};

ssize_t CBuffer::put(const void *data, size_t size) {
    if(len + size > sizeof(content)){
        return -1;
    }

    uint32_t start = (offset + len) % sizeof(content);
    uint32_t finish = (offset +  len + size) % sizeof(content);
    if(finish > start){
        memcpy(content + start, data, size);
    }else{
        size_t l = sizeof(content) - start;
        memcpy(content + start, data, l);
        memcpy(content, (const char*)data + l, finish);
    }
    len += size;
    assert(len <= sizeof(content));
    return (ssize_t)len;
}

size_t CBuffer::get(char* buff, size_t size){
    assert(size != 0);
    size = Min(len, size);

    uint32_t start = offset % sizeof(content);
    uint32_t finish = (offset + size) % sizeof(content);

    if(finish > start){
        memcpy(buff, content+ start , size);
        return size;
    }else{
        size_t l = sizeof(content) - start;
        memcpy(buff, content + start, l);
        memcpy(buff + l, content, finish);
        return size;
    }
}

void CBuffer::consume(size_t l){
    assert(l <= len);
    offset += l;
    len -= l;
}

char* CBuffer::end(){
    return content + ((offset + len) % sizeof(content));
}

SocketRWer::SocketRWer(int fd, const sockaddr_storage* peer, std::function<void(int, int)> errorCB):RWer(fd, std::move(errorCB)){
    setEvents(RW_EVENT::READ);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&SocketRWer::defaultHE;
    sockaddr_storage addr;
    if(peer && peer->ss_family == AF_UNIX){
        memset(&addr, 0, sizeof(addr));
        socklen_t len = sizeof(addr);
        if(getsockname(fd, (sockaddr *)&addr, &len)){
            LOGE("getsockname error: %s\n", strerror(errno));
            return;
        }
    }else{
        memset(&addr, 0, sizeof(addr));
        socklen_t len = sizeof(addr);
        if(getpeername(fd, (sockaddr *)&addr, &len)){
            LOGE("getpeername error: %s\n", strerror(errno));
            return;
        }
    }
    addrs.push(addr);
}

SocketRWer::SocketRWer(const char* hostname, uint16_t port, Protocol protocol,
               std::function<void(int, int)> errorCB,
               std::function<void(const sockaddr_storage&)> connectCB):
            RWer(std::move(errorCB), std::move(connectCB)), port(port), protocol(protocol)
{
    strcpy(this->hostname, hostname);
    stats = RWerStats::Resolving;
    AddJob(std::bind(&SocketRWer::query, this), 0, JOB_FLAGS_AUTORELEASE);
}

SocketRWer::~SocketRWer() {
}

void SocketRWer::query() {
    try{
        query_host(hostname, SocketRWer::Dnscallback, shared_from_this());
    }catch(...){
    }
}

void SocketRWer::Dnscallback(std::weak_ptr<void> param, int error, std::list<sockaddr_storage> addrs) {
    if(param.expired()){
        return;
    }
    std::shared_ptr<SocketRWer> rwer = std::static_pointer_cast<SocketRWer>(param.lock());
    if (error) {
        return rwer->ErrorHE(DNS_FAILED, error);
    }
    if(addrs.empty()){
        return rwer->ErrorHE(DNS_FAILED, 0);
    }

    for(auto& i: addrs){
        sockaddr_in6* addr6 = (sockaddr_in6*)&i;
        addr6->sin6_port = htons(rwer->port);
        rwer->addrs.push(i);
    }
    rwer->stats = RWerStats::Connecting;
    rwer->connect();
}

void SocketRWer::connectFailed(int error) {
    assert(!addrs.empty());
    RcdBlock(hostname, addrs.front());
    addrs.pop();
    if(getFd() >= 0){
        setFd(-1);
    }
    if(addrs.empty()) {
        //we have tried all addresses.
        return ErrorHE(CONNECT_FAILED, error);
    }
    this->connect();
}

void SocketRWer::connect() {
    if(stats != RWerStats::Connecting && stats != RWerStats::SslConnecting) {
        return;
    }
    assert(!addrs.empty());
    if(protocol == Protocol::TCP) {
        int fd = Connect(&addrs.front(), SOCK_STREAM);
        if (fd < 0) {
            con_failed_job = updatejob(con_failed_job,
                                       std::bind(&SocketRWer::connectFailed, this, errno), 0);
            return;
        }
        setFd(fd);
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT)) &SocketRWer::waitconnectHE;
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SocketRWer::connectFailed, this, ETIMEDOUT), 10000);
    } else if(protocol == Protocol::QUIC) {
        int fd = Connect(&addrs.front(), SOCK_DGRAM);
        if (fd < 0) {
            con_failed_job = updatejob(con_failed_job,
                                       std::bind(&SocketRWer::connectFailed, this, errno), 0);
            return;
        }
        setFd(fd);
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT)) &SocketRWer::waitconnectHE;
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SocketRWer::connectFailed, this, ETIMEDOUT), 10000);
    } else if(protocol == Protocol::UDP) {
        int fd = Connect(&addrs.front(), SOCK_DGRAM);
        if (fd < 0) {
            con_failed_job = updatejob(con_failed_job,
                                       std::bind(&SocketRWer::connectFailed, this, errno), 0);
            return;
        }
        setFd(fd);
        Connected(addrs.front());
    } else if(protocol == Protocol::ICMP) {
        auto addr = addrs.front();
        int fd = IcmpSocket(&addrs.front(), 0);
        if (fd > 0) {
            setFd(fd);
            Connected(addr);
            return;
        }
        //clear id, icmp header should be generated by user.
        ((sockaddr_in6*)&addr)->sin6_port = 0;
        fd = IcmpSocket(&addrs.front(), 1);
        if (fd > 0) {
            setFd(fd);
            Connected(addr);
            return;
        }
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SocketRWer::connectFailed, this, errno), 0);
        return;
    } else {
        LOGF("Unknow protocol: %d\n", protocol);
    }
}

void SocketRWer::Connected(const sockaddr_storage& addr) {
    deljob(&con_failed_job);
    RWer::Connected(addr);
}

void SocketRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR) || !!(events & RW_EVENT::READEOF)) {
        int error = checkSocket(__PRETTY_FUNCTION__ );
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SocketRWer::connectFailed, this, error), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        assert(!addrs.empty());
        Connected(addrs.front());
    }
}

const char *SocketRWer::getPeer() {
    static char peer[300];
    memset(peer, 0, sizeof(peer));
    if(hostname[0]){
        sprintf(peer, "<%s://%s:%d> ", protstr(protocol), hostname, port);
    }
    if(addrs.empty()){
        sprintf(peer + strlen(peer), "null");
        return peer;
    }
    auto addr = addrs.front();
    sprintf(peer + strlen(peer), "%s", storage_ntoa(&addr));
    if(addr.ss_family == AF_UNIX){
#if defined(SO_PEERCRED)
        struct ucred cred;
        socklen_t len = sizeof(struct ucred);
        if(getsockopt(getFd(), SOL_SOCKET, SO_PEERCRED, &cred, &len)){
            LOGE("Failed to get cred: %s\n", strerror(errno));
        }else{
            sprintf(peer + strlen(peer), ",uid=%d,pid=%d", cred.uid, cred.pid);
        }
#else
#ifdef LOCAL_PEERCRED
        struct xucred cred;
        socklen_t credLen = sizeof(cred);
        if(getsockopt(getFd(), SOL_LOCAL, LOCAL_PEERCRED, &cred, &credLen)){
            LOGE("Failed to get cred: %s\n", strerror(errno));
        }else{
            sprintf(peer + strlen(peer), ",uid=%d", cred.cr_uid);
        }
#endif
#ifdef LOCAL_PEERPID
        pid_t pid;
        socklen_t pid_size = sizeof(pid);
        if(getsockopt(getFd(), SOL_LOCAL, LOCAL_PEERPID, &pid, &pid_size)){
            LOGE("failed to call LOCAL_PEERPID: %s\n", strerror(errno));
        }else {
            sprintf(peer + strlen(peer), ",pid=%d", pid);
        }
#endif
#endif
    }
    return peer;
}

ssize_t SocketRWer::Write(const void* buff, size_t len, uint64_t){
    return write(getFd(), buff, len);
}

size_t StreamRWer::rlength() {
    return rb.length();
}

void StreamRWer::ConsumeRData() {
    if(rb.length()){
        char* buff = (char*)p_malloc(rb.length());
        buff_block wb{buff, rb.get(buff, rb.length())};
        readCB(wb);
        rb.consume(wb.offset);
    }
    if(stats == RWerStats::ReadEOF){
        buff_block wb{(void*)nullptr, 0};
        readCB(wb);
    }
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
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    // call consume after to avoid dup if eof.
    if(rb.length() && (stats != RWerStats::ReadEOF)){
        ConsumeRData();
    }
    if(rb.left() == 0){
        delEvents(RW_EVENT::READ);
    }
}

size_t PacketRWer::rlength() {
    return rb.length();
}

ssize_t PacketRWer::Read(void* buff, size_t len) {
    return read(getFd(), buff, len);
}

void PacketRWer::ConsumeRData() {
    if(rb.length()){
        buff_block bb{rb.data(), rb.length()};
        readCB(bb);
        rb.consume(bb.offset);
    }
    if(stats == RWerStats::ReadEOF){
        buff_block wb{(void*)nullptr, 0};
        readCB(wb);
    }
}

void PacketRWer::ReadData() {
    size_t left = 0;
    while((left = rb.left())){
        int ret = Read(rb.end(), left);
        if(ret > 0){
            rb.add((size_t)ret);
            ConsumeRData();
            continue;
        }
        if(ret == 0){
            stats = RWerStats::ReadEOF;
            break;
        }
        if(errno == EAGAIN){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(rb.left() == 0){
        delEvents(RW_EVENT::READ);
    }
}
