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
    addjob([this]{
        //这里使用job,因为shared_from_this不能在构造函数里面用
        //因为使用了shared_ptr，所以不存在对象已经被释放了的情况
        //但是返回时RWer有可能已经被Close了，DnsCallback需要处理这种情况
        query_host(this->hostname, SocketRWer::Dnscallback, shared_from_this());
    }, 0, JOB_FLAGS_AUTORELEASE);
}

SocketRWer::~SocketRWer() {
}

void SocketRWer::Dnscallback(std::shared_ptr<void> param, int error, std::list<sockaddr_storage> addrs) {
    std::shared_ptr<SocketRWer> rwer = std::static_pointer_cast<SocketRWer>(param);
    if(rwer->flags & RWER_CLOSING){
        return;
    }
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
    if(len == 0){
        assert(flags & RWER_SHUTDOWN);
        shutdown(getFd(), SHUT_WR);
        return 0;
    }
    return write(getFd(), buff, len);
}

size_t StreamRWer::rlength() {
    return rb.length();
}

void StreamRWer::ConsumeRData() {
    if(rb.length()){
        auto buff = std::make_shared<Block>(rb.length());
        Buffer wb{buff, rb.get((char*) buff->data(), rb.length())};
        size_t len = wb.len;
        readCB(wb);
        rb.consume(len - wb.len);
    }
    if(stats == RWerStats::ReadEOF && rb.length() == 0 && (flags & RWER_EOFDELIVED) == 0){
        Buffer wb{nullptr, 0};
        readCB(wb);
        flags |= RWER_EOFDELIVED;
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
            // Eof will send to handler after rb are consumed
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            break;
        }
        if(errno == EAGAIN){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(rb.length()){
        ConsumeRData();
    }
    if(rb.cap() == 0){
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
        Buffer bb{rb.data(), rb.length()};
        size_t len = bb.len;
        readCB(bb);
        rb.consume(len - bb.len);
    }
    if(stats == RWerStats::ReadEOF && rb.length() == 0 && (flags & RWER_EOFDELIVED) == 0){
        Buffer wb{nullptr};
        readCB(wb);
        flags |= RWER_EOFDELIVED;
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
            delEvents(RW_EVENT::READ);
            stats = RWerStats::ReadEOF;
            break;
        }
        if(errno == EAGAIN){
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(rb.cap() == 0){
        delEvents(RW_EVENT::READ);
    }
}
