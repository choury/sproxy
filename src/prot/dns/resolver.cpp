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

Resolver::Resolver(const char* host,
                   const std::function<void(std::list<sockaddr_storage>)>& addrcb,
                   const std::list<sockaddr_storage>& results):
    Ep(-1)
{
    strcpy(this->host, host);
    reply = AddJob(std::bind(addrcb, results), 0, 0);
}

void Resolver::readHE(RW_EVENT events) {
    if(!!(events & RW_EVENT::ERROR)){
        checkSocket("dns socket error");
        if(rawcb) {
            return rawcb(nullptr, 0);
        }
        if(addrcb) {
            return addrcb({});
        }
    }
    if(!!(events & RW_EVENT::READ)) {
        char buf[BUF_SIZE];
        int ret = read(getFd(), buf, sizeof(buf));
        if(ret <= 0) {
            LOGE("dns read error: %s\n", strerror(errno));
            return;
        }
        if(rawcb) {
            return rawcb(buf, ret);
        }
        if(addrcb) {
            Dns_Result result(buf, ret);
            if(result.id == 0){
                LOGE("invalid dns result\n");
                addrcb({});
                return;
            }
            if(result.type == 1){
                flags |= GETARES;
            }else if(result.type == 28){
                flags |= GETAAAARES;
            }
            if(!result.addrs.empty()){
                rcd.get_time = time(nullptr);
                rcd.ttl = result.ttl;
                for(auto i: result.addrs){
                    rcd.addrs.push_back(i);
                }
            }
            if((flags & GETARES) && (flags & GETAAAARES)){
                rcd_cache[host] = rcd;
                addrcb(rcd.addrs);
            }
        }
    }
}


Resolver::Resolver(int fd,
                   const char *host,
                   int type,
                   std::function<void(const char *, size_t)> rawcb):
    Ep(fd), rawcb(std::move(rawcb))
{
    strcpy(this->host, host);
    socklen_t socklen = sizeof(addr);
    getpeername(fd, (sockaddr*)&addr, &socklen);
    char buf[BUF_SIZE];
    write(fd, buf, Dns_Query(host, type, id_cur++).build((unsigned char*)buf));
    this->handleEvent = (void (Ep::*)(RW_EVENT))&Resolver::readHE;
    setEvents(RW_EVENT::READ);
}

Resolver::Resolver(int fd,
                   const char *host,
                   std::function<void(std::list<sockaddr_storage>)> addrcb):
    Ep(fd), addrcb(std::move(addrcb))
{
    strcpy(this->host, host);
    socklen_t socklen = sizeof(addr);
    getpeername(fd, (sockaddr*)&addr, &socklen);
    char buf[BUF_SIZE];
    write(fd, buf, Dns_Query(host, 1, id_cur++).build((unsigned char*)buf));
    if(opt.ipv6_enabled) {
        write(fd, buf, Dns_Query(host, 28, id_cur++).build((unsigned char*)buf));
    }else {
        flags |= GETAAAARES;
    }
    this->handleEvent = (void (Ep::*)(RW_EVENT))&Resolver::readHE;
    setEvents(RW_EVENT::READ);
}

Resolver::~Resolver(){
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
}
#endif

void flushdns(){
    rcd_cache.clear();
    getDnsConfig(&dnsConfig);
}

Resolver* query_host_real(const char* host,
                          std::function<void(std::list<sockaddr_storage>)> addrcb)
{
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }

    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        return nullptr;
    }

    sockaddr_storage addr = dnsConfig.server[rand() % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        return nullptr;
    }
    return new Resolver(fd, host, std::move(addrcb));
}

Resolver* query_host(const char* host, DNSCB func, void* param) {
    sockaddr_storage addr{};
    if(storage_aton(host, 0, &addr) == 1){
        std::list<sockaddr_storage> addrs = {addr};
        return new Resolver(host, std::bind(func, param, _1), addrs);
    }

    if (rcd_cache.count(host)) {
        auto& rcd = rcd_cache[host];
        if(rcd.get_time + (time_t)rcd.ttl > time(nullptr)){
            return new Resolver(host, std::bind(func, param, _1), rcd.addrs);
        }else{
            rcd_cache.erase(host);
        }
    }
    return query_host_real(host, std::bind(func, param, _1));
}

Resolver* query_dns(const char* host, int type, DNSRAWCB func, void* param) {
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
    }
    if (dnsConfig.namecount == 0) {
        LOGE("[DNS] can't get dns server\n");
        return nullptr;
    }
    auto addr = dnsConfig.server[rand() % dnsConfig.namecount];
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        return nullptr;
    }
    return new Resolver(fd, host, type, std::bind(func, param, _1, _2));
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

