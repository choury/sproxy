#include "dns.h"
#include "resolver.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "common/base.h"
#include "common/common.h"

#include <unordered_map>
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

HostResolver::HostResolver(int fd,
                   const char *host,
                   std::function<void(int, std::list<sockaddr_storage>, HostResolver*)> addrcb):
    Ep(fd), cb(std::move(addrcb))
{
    strcpy(this->host, host);
    char buf[BUF_SIZE];
    write(fd, buf, Dns_Query(host, 1, id_cur++).build((unsigned char*)buf));
    if(opt.ipv6_enabled) {
        write(fd, buf, Dns_Query(host, 28, id_cur++).build((unsigned char*)buf));
    }else {
        flags |= GETAAAARES;
    }
    this->handleEvent = (void (Ep::*)(RW_EVENT))&HostResolver::readHE;
    setEvents(RW_EVENT::READ);
    reply = AddJob(std::bind(cb, DNS_TIMEOUT, rcd.addrs, this),
                   dnsConfig.timeout * 1000, 0);
}


void HostResolver::readHE(RW_EVENT events) {
    if(!!(events & RW_EVENT::ERROR)){
        checkSocket("dns socket error");
        flags |= GETERROR;
        DelJob(&reply);
        return cb(DNS_SERVER_FAIL, {}, this);
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
                LOGE("invalid dns result\n");
                flags |= GETERROR;
                goto ret;
            }
            rcd.get_time = time(nullptr);
            rcd.ttl = result.ttl;
            if(result.type == 1){
                flags |= GETARES;
                for(auto i: result.addrs){
                    rcd.addrs.push_back(i);
                }
            }else if(result.type == 28){
                flags |= GETAAAARES;
                for(auto i: result.addrs){
                    rcd.addrs.push_front(i);
                }
            }
            if(!(flags & GETARES) || !(flags & GETAAAARES)) {
                return;
            }
            rcd_cache[host] = rcd;
        }
ret:
        DelJob(&reply);
        return cb(error, rcd.addrs, this);
    }
}

HostResolver::~HostResolver() {
    DelJob(&reply);
}


RawResolver::RawResolver(int fd,
                   const char *host,
                   int type,
                   std::function<void(const char *, size_t, RawResolver*)> rawcb):
    Ep(fd), cb(std::move(rawcb))
{
    char buf[BUF_SIZE];
    write(fd, buf, Dns_Query(host, type, id_cur++).build((unsigned char*)buf));
    this->handleEvent = (void (Ep::*)(RW_EVENT))&RawResolver::readHE;
    setEvents(RW_EVENT::READ);
    reply = AddJob(std::bind(rawcb, nullptr, 0, this), dnsConfig.timeout * 1000, 0);
}

void RawResolver::readHE(RW_EVENT events) {
    if(!!(events & RW_EVENT::ERROR)){
        checkSocket("dns socket error");
        DelJob(&reply);
        return cb(nullptr, 0, this);
    }
    if(!!(events & RW_EVENT::READ)) {
        DelJob(&reply);
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
    DelJob(&reply);
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
        defer([&line]{
            free(line);
            line = nullptr;
        });
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
    getDnsConfig(&dnsConfig);
}

static void query_host_real(int retries, const char* host, DNSCB func, std::weak_ptr<void> param){
    if(retries >= 3){
        AddJob(std::bind(func, param, DNS_SERVER_FAIL,
                         std::list<sockaddr_storage>{}), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        AddJob(std::bind(func, param, DNS_REFUSE,
                         std::list<sockaddr_storage>{}), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    sockaddr_storage addr = dnsConfig.server[retries % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        AddJob(std::bind(func, param, DNS_REFUSE,
                         std::list<sockaddr_storage>{}), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    auto addrcb = [](int retries, DNSCB func, std::weak_ptr<void> param,
                          int error, std::list<sockaddr_storage> addrs, HostResolver* resolver)
    {
        defer([resolver]{delete resolver;});
        if(error == 0){
            func(param, error, std::move(addrs));
            return;
        }
        if(error == DNS_TIMEOUT){
            if(addrs.empty()){
                query_host_real(retries+1, resolver->host, func, param);
            }else{
                func(param, 0, std::move(addrs));
            }
            return;
        }
        func(param, error, {});
    };
    new HostResolver(fd, host, std::bind(addrcb, retries, func, param, _1, _2, _3));
}

void query_host(const char* host, DNSCB func, std::weak_ptr<void> param) {
    sockaddr_storage addr{};
    if(storage_aton(host, 0, &addr) == 1){
        std::list<sockaddr_storage> addrs = {addr};
        AddJob(std::bind(func, param, 0, addrs), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    if (rcd_cache.count(host)) {
        auto& rcd = rcd_cache[host];
        if(rcd.get_time + (time_t)rcd.ttl > time(nullptr)){
            AddJob(std::bind(func, param, 0, rcd.addrs), 0, JOB_FLAGS_AUTORELEASE);
            return;
        }
        rcd_cache.erase(host);
    }
    return query_host_real(0, host, func, param);
}

void query_dns(const char* host, int type, DNSRAWCB func, std::weak_ptr<void> param) {
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        AddJob(std::bind(func, param, nullptr, 0), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    auto addr = dnsConfig.server[rand() % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        AddJob(std::bind(func, param, nullptr, 0), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }
    auto rawcb = [](DNSRAWCB func, std::weak_ptr<void> param,
            const char* data, size_t len, RawResolver* resolver){
        delete resolver;
        func(param, data, len);
    };
    new RawResolver(fd, host, type, std::bind(rawcb, func, param, _1, _2, _3));
}

void RcdDown(const char *hostname, const sockaddr_storage &addr) {
    LOG("[DNS] down for %s: %s\n", hostname, getaddrstring(&addr));
    auto cmpfunc = [](const sockaddr_storage& a, const sockaddr_storage& b) -> bool {
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
    };
    if (rcd_cache.count(hostname)) {
        auto& addrs  = rcd_cache[hostname].addrs;
        for (auto i = addrs.begin(); i != addrs.end(); ++i) {
            if(cmpfunc(addr, *i)){
                addrs.erase(i);
                addrs.push_back(addr);
                return;
            }
        }
    }
}


void dump_dns(Dumper dp, void* param){
    dp(param, "Dns server:\n");
    for(size_t i = 0; i < dnsConfig.namecount; i++) {
        dp(param, "  %s\n", getaddrstring(&dnsConfig.server[i]));
    }
    dp(param, "Dns cache:\n");
    for(const auto& i: rcd_cache){
        dp(param, "  %s: %ld\n", i.first.c_str(), i.second.get_time + i.second.ttl - time(nullptr));
        for(auto j: i.second.addrs){
            dp(param, "    %s\n", getaddrstring(&j));
        }
    }
}

