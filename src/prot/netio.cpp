#include "netio.h"
#include "multimsg.h"
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

SocketRWer::SocketRWer(int fd, const sockaddr_storage* src, std::function<void(int, int)> errorCB):RWer(fd, std::move(errorCB)){
    setEvents(RW_EVENT::READ);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&SocketRWer::defaultHE;
    if(src) {
        addrs.emplace(*src);
    }else {
        sockaddr_storage addr{};
        socklen_t len = sizeof(addr);
        if(getpeername(fd, (sockaddr *)&addr, &len)){
            LOGE("getpeername error <%d>: %s\n", getFd(), strerror(errno));
            return;
        }
        addrs.push(addr);
    }
}

SocketRWer::SocketRWer(const char* hostname, uint16_t port, Protocol protocol,
               std::function<void(int, int)> errorCB):
            RWer(std::move(errorCB)), port(port), protocol(protocol)
{
    strcpy(this->hostname, hostname);
    stats = RWerStats::Resolving;
    AddJob([this]{
        //这里使用job,因为shared_from_this不能在构造函数里面用
        //因为使用了shared_ptr，所以不存在对象已经被释放了的情况
        //但是返回时RWer有可能已经被Close了，DnsCallback需要处理这种情况
        query_host(this->hostname, SocketRWer::Dnscallback, shared_from_this());
    }, 0, JOB_FLAGS_AUTORELEASE);
}

SocketRWer::~SocketRWer() {
}

void SocketRWer::Dnscallback(std::shared_ptr<void> param, int error, const std::list<sockaddr_storage>& addrs) {
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

    for(const auto& i: addrs){
        sockaddr_in6 *addr6 = (sockaddr_in6*)&i;
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
    stats = RWerStats::Connecting;
    this->connect();
}

void SocketRWer::connect() {
    if(stats != RWerStats::Connecting) {
        return;
    }
    assert(!addrs.empty());
    if(protocol == Protocol::TCP) {
        int fd = Connect(&addrs.front(), SOCK_STREAM);
        if (fd < 0) {
            con_failed_job = UpdateJob(std::move(con_failed_job),
                                       ([this, error = errno]{connectFailed(error);}), 0);
            return;
        }
        setFd(fd);
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT)) &SocketRWer::waitconnectHE;
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   [this]{connectFailed(ETIMEDOUT);}, 10000);
    } else if(protocol == Protocol::QUIC) {
        int fd = Connect(&addrs.front(), SOCK_DGRAM);
        if (fd < 0) {
            con_failed_job = UpdateJob(std::move(con_failed_job),
                                       ([this, error = errno]{connectFailed(error);}), 0);
            return;
        }
        setFd(fd);
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT)) &SocketRWer::waitconnectHE;
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   [this]{connectFailed(ETIMEDOUT);}, 10000);
    } else if(protocol == Protocol::UDP) {
        int fd = Connect(&addrs.front(), SOCK_DGRAM);
        if (fd < 0) {
            con_failed_job = UpdateJob(std::move(con_failed_job),
                                       ([this, error = errno]{connectFailed(error);}), 0);
            return;
        }
        setFd(fd);
        connected(addrs.front());
    } else if(protocol == Protocol::ICMP) {
        auto addr = addrs.front();
        int fd = IcmpSocket(&addrs.front(), 0);
        if (fd > 0) {
            setFd(fd);
            connected(addr);
            return;
        }
        //clear id, icmp header should be generated by user.
        ((sockaddr_in6*)&addr)->sin6_port = 0;
        fd = IcmpSocket(&addrs.front(), 1);
        if (fd > 0) {
            setFd(fd);
            connected(addr);
            return;
        }
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   ([this, error = errno]{connectFailed(error);}), 0);
        return;
    } else {
        LOGF("Unknow protocol: %d\n", protocol);
    }
}

void SocketRWer::connected(const sockaddr_storage& addr) {
    con_failed_job.reset(nullptr);
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&SocketRWer::defaultHE;
    connectCB(addr);
    connectCB = [](const sockaddr_storage&){};
}

bool SocketRWer::IsConnected(){
    return stats == RWerStats::Connected;
}

void SocketRWer::SetConnectCB(std::function<void(const sockaddr_storage&)> cb) {
    if(IsConnected()){
        cb(addrs.front());
    } else {
        connectCB = std::move(cb);
    }
}

void SocketRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR) || !!(events & RW_EVENT::READEOF)) {
        con_failed_job =
                UpdateJob(std::move(con_failed_job),
                          ([this, error = checkSocket(__PRETTY_FUNCTION__ )]{
                              connectFailed(error);
                          }), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        assert(!addrs.empty());
        connected(addrs.front());
    }
}

Destination SocketRWer::getSrc() const {
    Destination src{};
    if(getFd() < 0) {
        snprintf(src.hostname, sizeof(src.hostname), "<null>");
        return src;
    }
    if(hostname[0]) {
        // connect (me -> peer)
        sockaddr_storage myaddr;
        socklen_t addr_len = sizeof(myaddr);
        if(getsockname(getFd(), (sockaddr*)&myaddr, &addr_len)){
            LOGE("failed to getsockname <%d>: %s\n", getFd(), strerror(errno));
            snprintf(src.hostname, sizeof(src.hostname), "<null>");
        } else {
            storage2Dest(&myaddr, addr_len, &src);
        }
    } else {
        // bind (peer -> me)
        sockaddr_storage peer{};
        if(addrs.empty()) {
            socklen_t addr_len = sizeof(peer);
            if(getpeername(getFd(), (sockaddr*)&peer, &addr_len)){
                LOGE("failed to getpeername <%d>: %s\n", getFd(), strerror(errno));
                snprintf(src.hostname, sizeof(src.hostname), "<null>");
            } else {
                storage2Dest(&peer, addr_len, &src);
            }
        } else {
            peer = addrs.front();
            storage2Dest(&peer, sizeof(sockaddr_storage), &src);
        }
        if(peer.ss_family == AF_UNIX){
#if defined(SO_PEERCRED)
            struct ucred cred;
            socklen_t len = sizeof(struct ucred);
            if(getsockopt(getFd(), SOL_SOCKET, SO_PEERCRED, &cred, &len)){
                LOGE("Failed to get cred: %s\n", strerror(errno));
            }else{
                snprintf(src.hostname + strlen(src.hostname), sizeof(src.hostname) - strlen(src.hostname),
                    ",uid=%d", cred.uid);
            }
#else
#ifdef LOCAL_PEERCRED
            struct xucred cred;
            socklen_t credLen = sizeof(cred);
            if(getsockopt(getFd(), SOL_LOCAL, LOCAL_PEERCRED, &cred, &credLen)){
                LOGE("Failed to get cred <%d>: %s\n", getFd(), strerror(errno));
            }else{
                snprintf(src.hostname + strlen(src.hostname), sizeof(src.hostname) - strlen(src.hostname),
                    ",uid=%d", cred.cr_uid);
            }
#endif
#ifdef LOCAL_PEERPID
            pid_t pid;
            socklen_t pid_size = sizeof(pid);
            if(getsockopt(getFd(), SOL_LOCAL, LOCAL_PEERPID, &pid, &pid_size)){
                LOGE("failed to call LOCAL_PEERPID <%d>: %s\n", getFd(), strerror(errno));
            } else {
                snprintf(src.hostname + strlen(src.hostname), sizeof(src.hostname) - strlen(src.hostname),
                    ",pid=%d", pid);
            }
#endif
#endif
        }
    }
    return src;
}

Destination SocketRWer::getDst() const {
    Destination dst{};
    if(protocol != Protocol::NONE) {
        strcpy(dst.protocol, protstr(protocol));
    }
    if(hostname[0]) {
        // connect (me -> peer)
        if(addrs.empty()) {
            strcpy(dst.protocol, protstr(protocol));
            strcpy(dst.hostname, hostname);
            dst.port = port;
        } else {
            storage2Dest(&addrs.front(), sizeof(sockaddr_storage), &dst);
        }
    } else {
        // bind (peer -> me)
        if(getFd() < 0) {
            snprintf(dst.hostname, sizeof(dst.hostname), "<null>");
            return dst;
        }
        sockaddr_storage myaddr;
        socklen_t addr_len = sizeof(myaddr);
        if(getsockname(getFd(), (sockaddr*)&myaddr, &addr_len)){
            LOGE("failed to getsockname <%d>: %s\n", getFd(), strerror(errno));
            snprintf(dst.hostname, sizeof(dst.hostname), "<null>");
        } else {
            storage2Dest(&myaddr, addr_len, &dst);
        }
    }
    return dst;
}


void SocketRWer::dump_status(Dumper dp, void *param) {
    if(hostname[0]) {
        dp(param, "SocketRWer <%d> (%s %s): rlen: %zu, wlen: %zu, stats: %d, event: %s\n",
           getFd(), hostname, dumpDest(getDst()).c_str(),
           rlength(0), wlen, (int)getStats(), events_string[(int)getEvents()]);
    } else {
        dp(param, "SocketRWer <%d> (%s -> %s): rlen: %zu, wlen: %zu, stats: %d, event: %s\n",
           getFd(), dumpDest(getSrc()).c_str(), dumpDest(getDst()).c_str(),
           rlength(0), wlen, (int)getStats(), events_string[(int)getEvents()]);
    }
}

/*
ssize_t SocketRWer::Write(const void* buff, size_t len, uint64_t){
    if(len == 0){
        assert(flags & RWER_SHUTDOWN);
        shutdown(getFd(), SHUT_WR);
        return 0;
    }
    return write(getFd(), buff, len);
}
 */

size_t StreamRWer::rlength(uint64_t) {
    return rb.length();
}

void StreamRWer::ConsumeRData(uint64_t id) {
    if(rb.length()){
        Buffer wb = rb.get();
        assert(wb.len != 0);
        wb.id = id;
        rb.consume(readCB(std::move(wb)));
    }
    if(rb.cap() == 0){
        delEvents(RW_EVENT::READ);
    }
    if(isEof() && (flags & RWER_EOFDELIVED) == 0){
        readCB({nullptr, id});
        flags |= RWER_EOFDELIVED;
    }
}

void StreamRWer::ReadData() {
    while(true) {
        size_t left = rb.left();
        if (left == 0) {
            break;
        }
        ssize_t ret = read(getFd(), rb.end(), left);
        if (ret > 0) {
            rb.append((size_t) ret);
            ConsumeRData(0);
            continue;
        } else if (ret == 0) {
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            break;
        } else if (errno == EAGAIN) {
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    ConsumeRData(0);
}

size_t PacketRWer::rlength(uint64_t) {
    return 0;
}

void PacketRWer::ConsumeRData(uint64_t) {
}

ssize_t PacketRWer::Write(std::set<uint64_t>& writed_list) {
    if(wbuff.empty()) {
        return 0;
    }else if(wbuff.size() == 1) {
        auto bb = wbuff.begin();
        LOGD(DRWER, "will write: %p: %zd\n", bb->data(), bb->len);
        int ret  = 0;
        if(bb->len > 0) {
            ret = write(getFd(), bb->data(), bb->len);
            LOGD(DRWER, "write: len: %zd, ret: %d\n", bb->len, ret);
            bb->reserve(ret);
        }
        writed_list = StripWbuff(ret);
        return ret;
    } else {
        std::vector<iovec> iovs;
        iovs.reserve(wbuff.size());
        for (const auto &bb: wbuff) {
            iovs.emplace_back(iovec{(void *) bb.data(), bb.len});
            if (iovs.size() >= IOV_MAX) {
                break;
            }
        }
        ssize_t ret = writem(getFd(), iovs.data(), iovs.size());
        size_t len = 0;
        if (ret <= 0) {
            LOGD(DRWER, "writem: iovs: %zd, ret: %zd\n", iovs.size(), ret);
            return ret;
        }
        auto it = wbuff.begin();
        for(size_t i = 0; i < (size_t)ret; i++) {
            assert(iovs[i].iov_len <= it->len);
            writed_list.emplace(it->id);
            len += iovs[i].iov_len;
            wlen -= iovs[i].iov_len;
            if(it->len == iovs[i].iov_len) {
                it = wbuff.erase(it);
            }else {
                it->reserve(iovs[i].iov_len);
                break;
            }
        }
        LOGD(DRWER, "writem: iovs: %zd, ret: %zd/%zd\n", iovs.size(), ret, len);
        return (ssize_t)len;
    }
}

void PacketRWer::ReadData() {
    while(true) {
        ssize_t ret = read(getFd(), rb, sizeof(rb));
        if (ret > 0) {
            readCB({rb, (size_t)ret});
            continue;
        }
        if (ret == 0) {
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            readCB(nullptr);
            flags |= RWER_EOFDELIVED;
        }else if (errno != EAGAIN) {
            ErrorHE(SOCKET_ERR, errno);
        }
        return;
    }
}
