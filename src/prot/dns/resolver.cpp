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
std::unordered_map<std::string, Dns_Rcd> hosts;

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
    (void)!write(fd, buf, Dns_Query(host, ns_t_a, id_cur++).build((unsigned char*)buf));
    if(opt.ipv6_enabled) {
        (void)!write(fd, buf, Dns_Query(host, ns_t_aaaa, id_cur++).build((unsigned char*)buf));
    }else {
        flags |= GETAAAARES;
    }
    handleEvent = (void (Ep::*)(RW_EVENT))&HostResolver::readHE;
    setEvents(RW_EVENT::READ);
    reply = AddJob([this]{cb(DNS_TIMEOUT, this);}, dnsConfig.timeout * 1000, 0);
    rcd.get_time = 0;
    rcd.ttl = 0xffffffff;
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
        return cb(ns_r_servfail, this);
    }
    if(!!(events & RW_EVENT::READ)) {
        int error = 0;
        char buf[BUF_SIZE];
        time_t now = time(nullptr);
        int ret = read(getFd(), buf, sizeof(buf));
        if(ret <= 0) {
            LOGE("dns read error: %s\n", strerror(errno));
            error = ns_r_servfail;
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
            if(result.type == ns_t_a){
                flags |= GETARES;
                for(auto i: result.addrs){
                    assert(i.ss_family == AF_INET);
                    rcd.addrs.emplace_back(i);
                }
            }else if(result.type == ns_t_aaaa){
                flags |= GETAAAARES;
                for(auto i: result.addrs){
                    assert(i.ss_family == AF_INET6);
                    rcd.addrs.emplace_front(i);
                }
            }
            if(rcd.get_time + rcd.ttl > now + result.ttl) {
                rcd.get_time = now;
                rcd.ttl = result.ttl;
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

void reload_hosts() {
}

#else
#define RESOLV_FILE "/etc/resolv.conf"
#define HOSTS_FILE  "/etc/hosts"
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

void reload_hosts() {
    if(opt.ignore_hosts) {
        return;
    }
    FILE *hosts_file = fopen(HOSTS_FILE, "r");
    if (hosts_file == nullptr) {
        LOGE("[DNS] open hosts file:%s failed:%s\n", HOSTS_FILE, strerror(errno));
        return;
    }
    hosts.clear();
    char* line = nullptr;
    size_t len = 0;
    while(getline(&line, &len, hosts_file) >= 0){
        if(len == 0 || line[0] == '#' || line[0] == '\n') {
            continue;
        }
        std::istringstream iss(line);
        std::string addr;
        iss >> addr;
        if (iss.fail()){
            continue;
        }
        sockaddr_storage  rcd{};
        if(storage_aton(addr.c_str(), DNSPORT, &rcd) != 1){
            LOGE("[DNS] %s is not a valid ip address\n", addr.c_str());
            continue;
        }
        std::string host;
        while(iss>>host) {
            if(hosts.count(host) == 0) {
                hosts.emplace(host, Dns_Rcd{});
            }
            hosts[host].addrs.emplace_back(rcd);
            LOGD(DDNS, "load host: %s -> %s\n", host.c_str(), addr.c_str());
        }
    }
    free(line);
    fclose(hosts_file);
    LOG("[DNS] loaded host: %zd entries\n", hosts.size());
}
#endif

void flushdns(){
    rcd_cache.clear();
    rcd_blacklist.clear();
    dnsConfig.namecount = 0;
}

static void query_host_real(int retries, const char* host, DNSCB func, std::shared_ptr<void> param){
    if(retries >= 3){
        return func(param, ns_r_servfail, std::list<sockaddr_storage>{}, 0);
    }
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
        reload_hosts();
    }

    if (hosts.count(host)) {
        return func(param, 0, rcdfilter(host, hosts[host].addrs), 0xefffffff);
    }

    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        return func(param, ns_r_refused, std::list<sockaddr_storage>{}, 0);
    }

    sockaddr_storage addr = dnsConfig.server[retries % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        return func(param, ns_r_refused, std::list<sockaddr_storage>{}, 0);
    }

    new HostResolver(fd, host,  [retries, func, param](int error, HostResolver* resolver) {
        defer([resolver]{delete resolver;});
        if(error == 0){
            func(param, 0, rcdfilter(resolver->host, resolver->rcd.addrs), resolver->rcd.ttl);
            return;
        }
        if (!resolver->rcd.addrs.empty()) {
            func(param, 0, rcdfilter(resolver->host, resolver->rcd.addrs), resolver->rcd.ttl);
            return;
        }
        if(error == ns_r_nxdomain) {
            func(param, error, {}, 0);
            return;
        }
        query_host_real(retries + 1, resolver->host, func, param);
    });
}

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param) {
    sockaddr_storage addr{};
    if(storage_aton(host, 0, &addr) == 1){
        return func(param, 0, std::list<sockaddr_storage>{addr}, 0xefffffff);
    }

    if (rcd_cache.count(host)) {
        auto& rcd = rcd_cache[host];
        int ttl = (int)rcd.get_time + rcd.ttl - (int)time(nullptr);
        if(ttl > 0){
            return func(param, 0, rcdfilter(host, rcd.addrs), ttl);
        }
        rcd_cache.erase(host);
    }
    return query_host_real(0, host, func, param);
}

void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param) {
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
        reload_hosts();
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        return func(param, nullptr, 0);
    }
    auto addr = dnsConfig.server[rand() % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        return func(param, nullptr, 0);
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
        dp(param, "  %s: %d\n", i.first.c_str(), (int)i.second.get_time + (int)i.second.ttl - (int)time(nullptr));
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

