#include "netio.h"
#include "resolver.h"
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
    assert(noafter(begin_pos, end_pos));
    uint32_t start = begin_pos % sizeof(content);
    uint32_t finish = end_pos % sizeof(content);
    if((finish > start) || (begin_pos == end_pos)){
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
    assert(noafter(begin_pos, end_pos));
    uint32_t start = begin_pos % sizeof(content);
    uint32_t finish = end_pos % sizeof(content);
    if((finish > start) || (begin_pos == end_pos)){
        return content + start;
    }else{
        char* buff = (char*)malloc(end_pos - begin_pos);
        size_t l = sizeof(content) - start;
        memcpy(buff, content + start, l);
        memcpy(buff + l, content, finish);
        return  buff;
    }
}

void CBuffer::consume(const char* data, size_t l){
    begin_pos += l;
    assert(noafter(begin_pos, end_pos));
    if(data < content || data >= content + sizeof(content)){
        free((char*)data);
    }
}

char* CBuffer::end(){
    return content + (end_pos % sizeof(content));
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
    connect();
}

SocketRWer::~SocketRWer() {
    delete resolver;
}

void SocketRWer::Dnscallback(void* param, std::list<sockaddr_storage> addrs) {
    SocketRWer* rwer = static_cast<SocketRWer*>(param);
    if (addrs.empty()) {
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

void SocketRWer::connect() {
    if(stats != RWerStats::Resolving && stats != RWerStats::Connecting) {
        return;
    }
    delete resolver;
    resolver = nullptr;
    if(stats == RWerStats::Resolving) {
        if(retry-- <= 0) {
            return ErrorHE(DNS_FAILED, 0);
        }
        assert(addrs.empty());
        // No address got before.
        resolver = query_host(hostname, SocketRWer::Dnscallback, this);
        if(resolver == nullptr) {
            con_failed_job = updatejob(con_failed_job, std::bind(&SocketRWer::connect, this), 0);
        }else {
            con_failed_job = updatejob(con_failed_job, std::bind(&SocketRWer::connect, this), 1000);
        }
        return;
    }
    int fd = getFd();
    if(fd >= 0) {
        //connected failed for top addr
        RcdDown(hostname, addrs.front());
        addrs.pop();
    }
    if(addrs.empty()) {
        //we have tried all addresses.
        return ErrorHE(CONNECT_TIMEOUT, 0);
    }

    if(protocol == Protocol::TCP) {
        fd = Connect(&addrs.front(), SOCK_STREAM);
        if (fd < 0) {
            return ErrorHE(SOCKET_ERR, errno);
        }
        setFd(fd);
        setEvents(RW_EVENT::WRITE);
        handleEvent = (void (Ep::*)(RW_EVENT)) &SocketRWer::waitconnectHE;
        con_failed_job = updatejob(con_failed_job, std::bind(&SocketRWer::connect, this), 500);
    } else if(protocol == Protocol::UDP) {
        fd = Connect(&addrs.front(), SOCK_DGRAM);
        if (fd < 0) {
            return ErrorHE(SOCKET_ERR, errno);
        }
        setFd(fd);
        Connected(addrs.front());
    } else if(protocol == Protocol::ICMP) {
        fd = IcmpSocket(&addrs.front());
        if (fd < 0) {
            return ErrorHE(SOCKET_ERR, errno);
        }
        setFd(fd);
        Connected(addrs.front());
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
        checkSocket(__PRETTY_FUNCTION__);
        return connect();
    }
    if (!!(events & RW_EVENT::WRITE)) {
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

ssize_t SocketRWer::Write(const void* buff, size_t len){
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
        ErrorHE(SOCKET_ERR, errno);
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
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    if(rb.left() == 0){
        delEvents(RW_EVENT::READ);
    }
}

#include <cxxabi.h>
extern "C" void dump_func(char* stack, int depth) {
#ifdef __linux__
    /*
     * ./src/sproxy(_ZN6Status7requestEP7HttpReqP9Requester+0xa92) [0x5574eb16f4b2] 
     * 通过'('找到函数名，然后通过'+'定位结束位置
     */
    char* begin_pos = nullptr;
    char* offset_pos = nullptr;
    for(char* p = stack; *p; p++){
        if(*p == '(') {
            begin_pos = p;
        }
        if(*p == '+' && begin_pos) {
            offset_pos = p;
        }
    }
    if(!begin_pos || !offset_pos){
        LOGE(" [%d] %s \n", depth, stack);
        return;
    }
    // 临时从'+'处截断，得到一个\0结束的字符串
    *offset_pos = 0;
    size_t size;
    int status;
    char* demangled = abi::__cxa_demangle(begin_pos+1, nullptr, &size, &status);
    // 恢复原状
    *offset_pos = '+';
    if(status){
        LOGE("[%d] %s \n", depth, stack);
        return;
    }
    //从开始位置，即'('，截断，用demangled的函数替换掉
    *begin_pos = 0;
    LOGE("[%d] %s(%s%s\n", depth, stack, demangled, offset_pos);
    free(demangled);
#elif __APPLE__
    (void)depth;
    /*
     * 4   sproxy   0x000000010d6b5e77 _ZN6Status7requestEP7HttpReqP9Requester + 823
     * 查找第4个字段的开始和结束位置，作为函数名
     */
    char* begin_pos = nullptr;
    char* end_pos = nullptr;
    int field = 0;
    for(char* p = stack; *p; field++){
        if(field == 3){
            begin_pos = p;
        }
        while(*p != ' ' && *p){
            p++;
        }
        if(begin_pos){
            end_pos = p;
            break;
        }
        while(*p == ' '){
            p++;
        }
    }

    // 临时从后面的空格处截断，得到一个\0结束的字符串
    *end_pos = 0;
    size_t size;
    int status;
    char* demangled = abi::__cxa_demangle(begin_pos, nullptr, &size, &status);
    // 恢复原状
    *end_pos = ' ';
    if(status){
        LOGE("%s \n", stack);
        return;
    }
    //从开始位置截断，用demangled的函数替换掉
    *begin_pos = 0;
    LOGE("%s%s%s\n", stack, demangled, end_pos);
    free(demangled);
#else
    LOGE("[%d] %s \n", depth, stack);
#endif
}

