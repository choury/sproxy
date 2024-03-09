#include "dns.h"
#include "resolver.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "common/base.h"
#include "common/common.h"

#include <unordered_map>
#include <unordered_set>
#include <sstream>
#include <utility>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>


#define BUF_SIZE 1500

static uint16_t id_cur = 1;
static DnsConfig dnsConfig;

std::unordered_map<std::string, Dns_Rcd> rcd_cache;

bool operator==(const sockaddr_storage& a, const sockaddr_storage& b) {
    if(a.ss_family != b.ss_family){
        return false;
    }
    if(a.ss_family == AF_INET6){
        const sockaddr_in6* a6 = (const sockaddr_in6*)&a;
        const sockaddr_in6* b6 = (const sockaddr_in6*)&b;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(in6_addr)) == 0;
    }
    if(a.ss_family == AF_INET) {
        const sockaddr_in* a4 = (const sockaddr_in*)&a;
        const sockaddr_in* b4 = (const sockaddr_in*)&b;
        return memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(in_addr)) == 0;
    }
    return false;
}

// The specialized hash function for `unordered_map` keys
struct hash_fn {
    std::size_t operator() (const sockaddr_storage& a) const {
        std::size_t h1 = std::hash<uint8_t>()(a.ss_family);
        std::size_t h2 = 0;
        if(a.ss_family == AF_INET6){
#if __APPLE__
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.__u6_addr.__u6_addr32[0]);
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.__u6_addr.__u6_addr32[1])<<1;
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.__u6_addr.__u6_addr32[2])<<2;
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.__u6_addr.__u6_addr32[3])<<3;
#else
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.s6_addr32[0]);
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.s6_addr32[1])<<1;
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.s6_addr32[2])<<2;
            h2 ^= std::hash<uint32_t>()(((const sockaddr_in6*)&a)->sin6_addr.s6_addr32[3])<<3;
#endif
        } else {
            h2 = std::hash<uint32_t>()(((const sockaddr_in*)&a)->sin_addr.s_addr);
        }
        return h2 ^ (h1 << 8);
    }
};

std::unordered_map<std::string, std::unordered_set<sockaddr_storage, hash_fn>> rcd_blacklist;

std::list<sockaddr_storage> rcdfilter(const std::string& host, const std::list<sockaddr_storage>& rcd_list) {
    if (rcd_blacklist.count(host) == 0){
        return rcd_list;
    }
    std::list<sockaddr_storage> ret;
    const auto& blacklist = rcd_blacklist[host];
    for(auto i = rcd_list.rbegin(); i != rcd_list.rend(); ++i){
        if(blacklist.count(*i) == 0){
            ret.push_front(*i);
        }else {
            ret.push_back(*i);
        }
    }
    return ret;
}

HostResolver::HostResolver(int fd, const char *host, std::function<void(int, HostResolver*)> addrcb):
    Ep(fd), cb(std::move(addrcb))
{
    strcpy(this->host, host);
    char buf[BUF_SIZE];
    (void)!write(fd, buf, Dns_Query(host, 1, id_cur++).build((unsigned char*)buf));
    if(opt.ipv6_enabled) {
        (void)!write(fd, buf, Dns_Query(host, 28, id_cur++).build((unsigned char*)buf));
    }else {
        flags |= GETAAAARES;
    }
    handleEvent = (void (Ep::*)(RW_EVENT))&HostResolver::readHE;
    setEvents(RW_EVENT::READ);
    reply = AddJob([this]{cb(DNS_TIMEOUT, this);}, dnsConfig.timeout * 1000, 0);
}


void HostResolver::readHE(RW_EVENT events) {
    if(!!(events & RW_EVENT::ERROR)){
        checkSocket("dns socket error");
        sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        getpeername(getFd(), (sockaddr *)(&addr), &len);
        LOGE("[DNS] addr: %s\n", getaddrstring(&addr));
        flags |= GETERROR;
        reply.reset(nullptr);
        return cb(DNS_SERVER_FAIL, this);
    }
    if(!!(events & RW_EVENT::READ)) {
        int error = 0;
        char buf[BUF_SIZE];
        int ret = read(getFd(), buf, sizeof(buf));
        if(ret <= 0) {
            LOGE("dns read error: %s\n", strerror(errno));
            error = DNS_SERVER_FAIL;
            goto ret;
        }
        {
            Dns_Result result(buf, ret);
            error = result.error;
            if(result.error){
                LOGE("(%s) dns result error: %d\n", host, result.error);
                flags |= GETERROR;
                goto ret;
            }
            rcd.get_time = time(nullptr);
            rcd.ttl = result.ttl;
            if(result.type == 1){
                flags |= GETARES;
                for(auto i: result.addrs){
                    assert(i.ss_family == AF_INET);
                    rcd.addrs.emplace_back(i);
                }
            }else if(result.type == 28){
                flags |= GETAAAARES;
                for(auto i: result.addrs){
                    assert(i.ss_family == AF_INET6);
                    rcd.addrs.emplace_front(i);
                }
            }
            if(!(flags & GETARES) || !(flags & GETAAAARES)) {
                return;
            }
            if(!rcd.addrs.empty()) {
                //如果没有地址，那么ttl就是0xffffffff，不能缓存
                rcd_cache.emplace(host, rcd);
            }
        }
ret:
        reply.reset(nullptr);
        return cb(error, this);
    }
}

HostResolver::~HostResolver() {
}


RawResolver::RawResolver(int fd,
                   const char *host,
                   int type,
                   std::function<void(const char *, size_t, RawResolver*)> rawcb):
    Ep(fd), cb(std::move(rawcb))
{
    char buf[BUF_SIZE];
    (void)!write(fd, buf, Dns_Query(host, type, id_cur++).build((unsigned char*)buf));
    handleEvent = (void (Ep::*)(RW_EVENT))&RawResolver::readHE;
    setEvents(RW_EVENT::READ);
    reply = AddJob([this]{cb(nullptr, 0, this);}, dnsConfig.timeout * 1000, 0);
}

void RawResolver::readHE(RW_EVENT events) {
    if(!!(events & RW_EVENT::ERROR)){
        checkSocket("dns socket error");
        reply.reset(nullptr);
        return cb(nullptr, 0, this);
    }
    if(!!(events & RW_EVENT::READ)) {
        reply.reset(nullptr);
        char buf[BUF_SIZE];
        int ret = read(getFd(), buf, sizeof(buf));
        if(ret <= 0) {
            LOGE("dns read error: %s\n", strerror(errno));
            return cb(nullptr, 0, this);
        }
        return cb(buf, ret, this);
    }
}


RawResolver::~RawResolver(){
}

#ifdef __ANDROID__
extern std::vector<std::string> getDns();
void getDnsConfig(struct DnsConfig* config){
    config->namecount = 0;
    std::vector<std::string> dns = getDns();
    int get = 0;
    for(const auto& i: dns){
        if((size_t)get == sizeof(config->server)/sizeof(config->server[0])){
            break;
        }
        sockaddr_storage  addr{};
        if(storage_aton(i.c_str(), DNSPORT, &addr) != 1){
            LOGE("[DNS] %s is not a valid ip address\n", i.c_str());
            continue;
        }
        if(!opt.ipv6_enabled && addr.ss_family == AF_INET6){
            continue;
        }
        LOG("[DNS] set dns server: %s\n", i.c_str());
        config->server[get++] = addr;
    }
    config->namecount = get;
    config->timeout = 5;
}

#else
#define RESOLV_FILE "/etc/resolv.conf"
void getDnsConfig(struct DnsConfig* config){
    config->namecount = 0;
    FILE *res_file = fopen(RESOLV_FILE, "r");
    if (res_file == nullptr) {
        LOGE("[DNS] open resolv file:%s failed:%s\n", RESOLV_FILE, strerror(errno));
        return;
    }
    int get = 0;
    char* line = nullptr;
    size_t len = 0;
    while(getline(&line, &len, res_file) >= 0){
        if((size_t)get >= sizeof(config->server)/sizeof(config->server[0])){
            break;
        }
        std::istringstream iss(line);
        std::string command;
        iss >> command;
        if (command != "nameserver"){
            continue;
        } 
        std::string server;
        iss >> server;
        sockaddr_storage  addr{};
        if(storage_aton(server.c_str(), DNSPORT, &addr) != 1){
            LOGE("[DNS] %s is not a valid ip address\n", server.c_str());
            continue;
        }
        if(!opt.ipv6_enabled && addr.ss_family == AF_INET6){
            continue;
        }
        LOG("[DNS] set dns server: %s\n", server.c_str());
        config->server[get++] = addr;
    }
    free(line);
    fclose(res_file);
    config->namecount = get;
    config->timeout = 5;
}
#endif

void flushdns(){
    rcd_cache.clear();
    rcd_blacklist.clear();
    getDnsConfig(&dnsConfig);
}

static void query_host_real(int retries, const char* host, DNSCB func, std::shared_ptr<void> param){
    if(retries >= 3){
        AddJob(([func, param]{func(param, DNS_SERVER_FAIL, std::list<sockaddr_storage>{});}),
               0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        AddJob(([func, param]{func(param, DNS_REFUSE, std::list<sockaddr_storage>{});}),
               0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    sockaddr_storage addr = dnsConfig.server[retries % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        AddJob(([func, param]{func(param, DNS_REFUSE, std::list<sockaddr_storage>{});}),
               0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    new HostResolver(fd, host,  [retries, func, param](int error, HostResolver* resolver) {
        defer([resolver]{delete resolver;});
        if(error == 0){
            func(param, 0, rcdfilter(resolver->host, resolver->rcd.addrs));
            return;
        }
        if (!resolver->rcd.addrs.empty()) {
            func(param, 0, rcdfilter(resolver->host, resolver->rcd.addrs));
            return;
        }
        if(error == DNS_NAME_ERROR) {
            func(param, error, {});
            return;
        }
        query_host_real(retries + 1, resolver->host, func, param);
    });
}

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param) {
    sockaddr_storage addr{};
    if(storage_aton(host, 0, &addr) == 1){
        AddJob(([func, param, addrs = std::list<sockaddr_storage>{addr}]{
            func(param, 0, addrs);
        }), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    if (rcd_cache.count(host)) {
        auto& rcd = rcd_cache[host];
        if(rcd.get_time + (time_t)rcd.ttl > time(nullptr)){
            AddJob(([func, param, addrs = rcdfilter(host, rcd.addrs)]{
                func(param, 0, addrs);
            }), 0, JOB_FLAGS_AUTORELEASE);
            return;
        }
        rcd_cache.erase(host);
    }
    return query_host_real(0, host, func, param);
}

void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param) {
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        AddJob(([func, param]{func(param, nullptr, 0);}), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    auto addr = dnsConfig.server[rand() % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        AddJob(([func, param]{func(param, nullptr, 0);}), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    new RawResolver(fd, host, type, [func, param](const char* data, size_t len, RawResolver* resolver){
        defer([resolver]{delete resolver;});
        func(param, data, len);
    });
}

void RcdBlock(const char *hostname, const sockaddr_storage &addr) {
    const char* addrstring = getaddrstring(&addr);
    if(strcmp(hostname, addrstring) == 0){
        //we shouldn't block raw ip
        return;
    }
    LOG("[DNS] down for %s: %s\n", hostname, addrstring);
    if(rcd_cache.count(hostname) == 0){
        return;
    }
    if(!rcd_blacklist.count(hostname)){
        rcd_blacklist.emplace(hostname, std::unordered_set<sockaddr_storage, hash_fn>{});
    }
    rcd_blacklist[hostname].emplace(addr);
}


void dump_dns(Dumper dp, void* param){
    dp(param, "======================================\n");
    dp(param, "Dns server:\n");
    for(size_t i = 0; i < dnsConfig.namecount; i++) {
        dp(param, "  %s\n", getaddrstring(&dnsConfig.server[i]));
    }
    dp(param, "--------------------------------------\n");
    dp(param, "Dns cache:\n");
    for(const auto& i: rcd_cache){
        dp(param, "  %s: %ld\n", i.first.c_str(), i.second.get_time + i.second.ttl - time(nullptr));
        for(const auto& j: rcdfilter(i.first, i.second.addrs)){
            dp(param, "    %s\n", getaddrstring(&j));
        }
    }
    dp(param, "--------------------------------------\n");
    dp(param, "Dns blacklist:\n");
    for(const auto& i: rcd_blacklist){
        dp(param, "  %s:\n", i.first.c_str());
        for(const auto& j: i.second){
            dp(param, "    %s\n", getaddrstring(&j));
        }
    }
    dp(param, "======================================\n");
}

