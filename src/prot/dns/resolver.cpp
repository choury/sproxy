#include "dns.h"
#include "resolver.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "misc/net.h"
#include "misc/job.h"
#include "hook/hook.h"
#include "hook/reflect.h"
#include "prot/ep.h"
#include "prot/memio.h"
#include "prot/http/http_header.h"
#include "res/responser.h"

#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <sstream>
#include <utility>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define BUF_SIZE 1500

//单族地址记录(A或AAAA)，独立计时；过期即需重查该族
struct Dns_Addr_Rcd {
    std::list<sockaddr_storage> addrs;
    uint32_t ttl = 0xefffffff;
    time_t get_time = 0;
    bool fresh() const {
        return (ttl != 0xefffffff) && (get_time + ttl > time(nullptr));
    }
};

//HTTPS RR(type 65)的ech记录，独立计时；未过期的空config为负缓存(确定无ech)
struct Dns_Ech_Rcd {
    std::string config;    //序列化的ECHConfigList
    uint32_t ttl = 0xefffffff;
    time_t get_time = 0;
    bool fresh() const {
        return (ttl != 0xefffffff) && (get_time + ttl > time(nullptr));
    }
};

//一个域名的DNS缓存条目(rcd_cache)：A/AAAA/ech三部分各自独立计时，
//某部分过期只重查该部分，其余部分不受影响
struct Dns_Rcd{
    Dns_Addr_Rcd a;
    Dns_Addr_Rcd aaaa;
    Dns_Ech_Rcd ech;

    //未过期的ech配置，无ech知识或负缓存返回空串
    std::string get_ech() const {
        return ech.fresh() ? ech.config : std::string{};
    }
    void reflect(IVisitor& v) {
        reflect_all(a.addrs, a.ttl, a.get_time,
                    aaaa.addrs, aaaa.ttl, aaaa.get_time,
                    ech.config, ech.ttl, ech.get_time);
    }
};

static uint16_t id_cur = 1;
static DnsConfig dnsConfig;

std::unordered_map<std::string, Dns_Rcd> rcd_cache;
//hosts文件表：无TTL概念，不进rcd_cache
static std::unordered_map<std::string, std::list<sockaddr_storage>> hosts;

class ResolverBase{
protected:
    std::function<void(const char*, size_t)> dnscb = nullptr;
public:
    virtual ~ResolverBase() {}
    virtual int query(const char* host, int type, std::function<void(const char*, size_t)>  cb) = 0;
    virtual int query(const void* data, size_t len, std::function<void(const char*, size_t)>  cb) = 0;
    template<typename V>
    void reflect(V&) {}
};

//DoH解析器：DNS报文作为POST body发往DoH服务器
class HttpResolver: public ResolverBase {
    Job reply = nullptr;
    struct Status {
        std::shared_ptr<HttpReqHeader>   req;
        std::shared_ptr<MemRWer>          rw;
        std::shared_ptr<IMemRWerCallback> cb;
        std::string data;
    }status{};
    std::function<void(const char*, size_t)> dnscb = nullptr;
    //回调前先取消超时job，避免成功/失败回调后超时job再触发一次
    void fire(const char* data, size_t len) {
        reply.reset(nullptr);
        dnscb(data, len);
    }
public:
    explicit HttpResolver(const Destination& server) {
        char buff[HEADLENLIMIT];
        int headlen = snprintf(buff, sizeof(buff),
            "POST %s/dns-query HTTP/1.1" CRLF
            "content-type: application/dns-message" CRLF CRLF, dumpDest(server).c_str());
        status.req = UnpackHttpReq(buff, headlen);
        memcpy(&status.req->Dest, &server, sizeof(Destination));
        status.req->Dest.system_resolve = true;
        if(server.credit.user[0]) {
            status.req->set("Authorization", encodeCredit(&server.credit));
        }

        status.cb = std::make_shared<IMemRWerCallback>()->onData([this](Buffer&& bb) {
            if (bb.len == 0) {
                status.cb = nullptr;
                fire(status.data.data(), status.data.size());
                return 0;
            }
            status.data.append((const char*)bb.data(), bb.len);
            return (int)bb.len;
        })->onHeader([this](std::shared_ptr<HttpResHeader> res) {
            LOGD(DDNS, "http dns response: %s\n", res->status);
            if (memcmp(res->status, "200", 3) == 0) {
                return;
            }
            LOGE("[DNS] http dns error: %s\n", res->status);
            status.cb = nullptr;
            fire(nullptr, 0);
        })->onCap([] {
            return BUF_LEN;
        })->onWrite([](uint64_t){})->onSignal([](Signal){});
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
        status.rw = std::make_shared<MemRWer>(Destination{.hostname = "localhost"}, status.req->Dest, status.cb);
#pragma GCC diagnostic pop
    }

    virtual ~HttpResolver() override {
        status.rw->push_signal(Signal::CHANNEL_ABORT);
    }

    virtual int query(const void *data, size_t len, std::function<void(const char *, size_t)> cb) override {
        dnscb = std::move(cb);
        status.req->set("content-length", len);
        status.rw->push_data({data, len});
        status.rw->push_data({nullptr});
        distribute(status.req, status.rw);
        reply = AddJob([this]{fire(nullptr, 0);}, dnsConfig.timeout * 1000, 0);
        return 0;
    }

    virtual int query(const char* host, int type, std::function<void(const char *, size_t)> cb) override {
        dnscb = std::move(cb);
        char buf[BUF_SIZE];
        int len = Dns_Query(host, type, id_cur++).build((unsigned char*)buf, sizeof(buf));
        status.req->set("content-length", len);
        status.rw->push_data({buf, (size_t)len});
        status.rw->push_data({nullptr});
        distribute(status.req, status.rw);
        reply = AddJob([this]{fire(nullptr, 0);}, dnsConfig.timeout * 1000, 0);
        return 0;
    }
};

//明文UDP解析器
class RawResolver: public Ep, public ResolverBase{
    Job reply = nullptr;
    std::function<void(const char*, size_t)> cb = nullptr;
    //回调前先取消超时job，避免数据回调后超时job再触发一次
    void fire(const char* data, size_t len) {
        reply.reset(nullptr);
        cb(data, len);
    }
    void readHE(RW_EVENT events) {
        if(!!(events & RW_EVENT::ERROR)){
            checkSocket("dns socket error");
            return fire(nullptr, 0);
        }
        if(!!(events & RW_EVENT::READ)) {
            char buf[BUF_SIZE];
            int ret = read(getFd(), buf, sizeof(buf));
            if(ret <= 0) {
                LOGE("dns read error: %s\n", strerror(errno));
                return fire(nullptr, 0);
            }
            return fire(buf, ret);
        }
    }
public:
    explicit RawResolver(const sockaddr_storage& server): Ep(Connect(&server, SOCK_DGRAM, nullptr)) {
        handleEvent = (void (Ep::*)(RW_EVENT))&RawResolver::readHE;
    }
    virtual ~RawResolver() override {}

    virtual int query(const char *host, int type, std::function<void(const char *, size_t)> rawcb) override {
        if(getFd() < 0){
            return -1;
        }
        cb = std::move(rawcb);
        char buf[BUF_SIZE];
        if(write(getFd(), buf, Dns_Query(host, type, id_cur++).build((unsigned char*)buf, sizeof(buf))) < 0) {
            LOGE("write dns query failed: %s\n", strerror(errno));
        }
        setEvents(RW_EVENT::READ);
        reply = AddJob([this]{fire(nullptr, 0);}, dnsConfig.timeout * 1000, 0);
        return 0;
    }

    virtual int query(const void *data, size_t len, std::function<void(const char *, size_t)> rawcb) override {
        if(getFd() < 0){
            return -1;
        }
        cb = std::move(rawcb);
        if(write(getFd(), data, len) < 0) {
            LOGE("write raw dns query failed: %s\n", strerror(errno));
        }
        setEvents(RW_EVENT::READ);
        reply = AddJob([this]{fire(nullptr, 0);}, dnsConfig.timeout * 1000, 0);
        return 0;
    }
};

#define GOTARES     0x10000
#define GOTAAAARES  0x20000
#define GOTECHRES   0x40000
#define GOTRETURN   0x80000  //cb已回调过一次，后续到达的记录只更新缓存
//A/AAAA(/HTTPS)按族并发解析，自毁式生命周期：全部子查询结束后delete this
class HostResolver {
    uint32_t flags = 0;
    std::function<void(int)> cb = nullptr;
    ResolverBase* AResolver = nullptr;
    ResolverBase* AAAAResolver = nullptr;
    ResolverBase* HTTPSResolver = nullptr;
    uint64_t ASendTime = 0;
    uint64_t AAAASendTime = 0;
    // 我知道这个server可能在查询期间被重新配置，但是因为它是存放在dnsConfig的静态数组
    // 即使getDnsConfig重置了dnsConfig，而我们只访问rtt, 写了一个无效server中的rtt也是无害的
    DnsServer* server = nullptr;
    int pending = 0;   //未完成的子查询数，归零即自毁(query_host_real不持有引用)

    //A/AAAA子查询的公共回调：本族查询就此结束(无论成败)。成功则本族结论即时落缓存
    //(不等另一族)；全族结束即回调一次，之后迟到的记录只更新缓存不再回调
    void handle_addr(const char* data, size_t len, uint32_t resflag, uint64_t sendtime) {
        bool want_v6 = resflag == GOTAAAARES;
        Dns_Result result(data, len);
        flags |= resflag;
        if(result.error){
            LOGE("(%s) dns result error: %d\n", host, result.error);
            if(!(flags & GOTRETURN)) {
                flags |= GOTRETURN;
                cb(result.error);
            }
        }else{
            if(server) server->rtt = (getutime() - sendtime) / 1000.0;
            Dns_Addr_Rcd& res = want_v6 ? 
                    rcd_cache.try_emplace(host).first->second.aaaa : 
                    rcd_cache.try_emplace(host).first->second.a;
            res.addrs.clear();
            for(const auto& addr: result.addrs){
                res.addrs.emplace_back(addr);
            }
            res.ttl = result.ttl;
            res.get_time = time(nullptr);
        }
        sub_done();
    }

    //HTTPS子查询回调：结果只写ech记录，不参与对外回调；超时/畸形不缓存，
    //下次ech过期重查时随HostResolver再发
    void handle_https(const char* data, size_t len) {
        std::string ech;
        uint32_t ttl = 0;
        if(data != nullptr && parse_ech_configs(data, len, ech, &ttl) == 0) {
            bool negative = ech.empty();
            if(!negative) {
                LOGD(DDNS, "(%s) ech config: %zd bytes, ttl: %u\n", host, ech.size(), ttl);
            }
            //条目可以只有ech知识(地址子记录天然过期)；已新鲜则不覆盖，
            //查询期间可能已被ECH拒收的retry configs更新过
            auto it = rcd_cache.try_emplace(this->host);
            if(!it.first->second.ech.fresh()) {
                it.first->second.ech.config = std::move(ech);
                it.first->second.ech.ttl = negative ? std::max(std::min(ttl, 300u), 60u) : ttl;
                it.first->second.ech.get_time = time(nullptr);
            }
        }
        sub_done();
    }

    //子查询收尾：全部完成后自毁。必须在各handler最后调用，删除发生在子resolver回调栈内
    void sub_done() {
        if(--pending > 0) {
            return;
        }
        if(!(flags & GOTRETURN)) {
            flags |= GOTRETURN;
            cb(0);
        }
        delete this;
    }
public:
    char host[DOMAINLIMIT];
    explicit HostResolver(DnsServer* server): server(server) {
        AResolver = new RawResolver(server->addr);
        if(opt.ipv6_enabled) {
            AAAAResolver = new RawResolver(server->addr);
        }
        if(opt.ech_mode != Disable) {
            HTTPSResolver = new RawResolver(server->addr);
        }
    }
    explicit HostResolver(const Destination& server) {
        AResolver = new HttpResolver(server);
        if(opt.ipv6_enabled) {
            AAAAResolver = new HttpResolver(server);
        }
        if(opt.ech_mode != Disable) {
            HTTPSResolver = new HttpResolver(server);
        }
    }
    ~HostResolver() {
        delete AResolver;
        delete AAAAResolver;
        delete HTTPSResolver;
    }

    //qflags的GETARES/GETAAAARES/GETECHRES位是最终子查询集(query_host已按
    //新鲜度过滤)，为0的族不查询，直接视为已结束(调用方持有新鲜缓存)。
    //GETRETURN位表示调用方已回调过(后台补ech)，本次结果只进缓存不再回调
    int query(const char *host, std::function<void(int)> addrcb, uint32_t qflags) {
        strcpy(this->host, host);
        if(qflags == 0){
            addrcb(0);
            delete this;
            return 0;
        }
        cb = std::move(addrcb);
        uint64_t now = getutime();
        if(qflags & QARES) {
            ASendTime = now;
            if (AResolver->query(host, ns_t_a, [this](const char* data, size_t len) {
                handle_addr(data, len, GOTARES, ASendTime);
            }) == 0) {
                pending++;
            }else{
                flags |= GOTARES; //启动失败视作本族已结束，否则全族齐备的判断永远不成立
            }
        }
        //AAAAResolver/HTTPSResolver仅在ipv6/ech启用时创建，对应的位已在query_host清除
        if(qflags & QAAAARES) {
            AAAASendTime = now;
            if(AAAAResolver->query(host, ns_t_aaaa, [this](const char* data, size_t len) {
                handle_addr(data, len, GOTAAAARES, AAAASendTime);
            }) == 0) {
                pending++;
            } else {
                flags |= GOTAAAARES;
            }
        }
        if(qflags & QECHRES) {
            if(HTTPSResolver->query(host, ns_t_https, [this](const char* data, size_t len) {
                handle_https(data, len);
            }) == 0) {
                pending++;
            } else {
                flags |= GOTECHRES;
            }
        }
        if(pending == 0) {
            return -1;
        }
        return 0;
    }

    //HOOK_BPF序列化需要
    void reflect(IVisitor& v) {
        reflect_all(host);
    }
};

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

#ifdef ANDROID_APP
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
        config->server[get++] = {addr, 0.0};
    }
    config->namecount = get;

    memset(&config->doh, 0, sizeof(config->doh));
    if(opt.doh_server) {
        if(opt.doh_server[0]) {
            parseDest(opt.doh_server, &config->doh);
        }else if(opt.Server.hostname[0]) {
            config->doh = opt.Server;
        }
    }
    config->timeout = 5;
}

void reload_hosts() {
}

#else
#ifdef TERMUX
#define RESOLV_FILE "/data/data/com.termux/files/usr/etc/resolv.conf"
#define HOSTS_FILE  "/data/data/com.termux/files/usr/etc/hosts"
#else
#define RESOLV_FILE "/etc/resolv.conf"
#define HOSTS_FILE  "/etc/hosts"
#endif

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
        config->server[get++] = {addr, 0.0};
    }
    free(line);
    fclose(res_file);
    config->namecount = get;

    memset(&config->doh, 0, sizeof(config->doh));
    if(opt.doh_server) {
        if(opt.doh_server[0]) {
            parseDest(opt.doh_server, &config->doh);
        }else if(opt.Server.hostname[0]) {
            config->doh = opt.Server;
        }
    }
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
                hosts.emplace(host, std::list<sockaddr_storage>{});
            }
            hosts[host].emplace_back(rcd);
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

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static void query_host_real(int retries, const char* host, DNSCB func, std::shared_ptr<void> param, uint32_t flags){
    HOOK_BPF(retries, host, flags);
    if(retries >= 3){
        return func(Host_Result{.param = std::move(param), .error = ns_r_servfail});
    }
    uint32_t qflags = flags & (QARES | QAAAARES | QECHRES);
    if(auto it = rcd_cache.find(host); it != rcd_cache.end()) {
        auto& rcd = it->second;
        if((flags & QARES) && rcd.a.fresh()) {
            qflags &= ~QARES;
        }
        if((flags & QAAAARES) && rcd.aaaa.fresh()) {
            qflags &= ~QAAAARES;
        }
        if((flags & QECHRES) && rcd.ech.fresh()) {
            qflags &= ~QECHRES;
        }
    }

    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
        reload_hosts();
    }

    HostResolver* resolver = nullptr;
    if(dnsConfig.doh.hostname[0] && !(flags & RAWRESOLVER)) {
        resolver = new HostResolver(dnsConfig.doh);
    }else{
        if (dnsConfig.namecount == 0) {
            LOGE("[DNS] can't get dns server\n");
            return func(Host_Result{.param = std::move(param), .error = ns_r_refused});
        }
        resolver = new HostResolver(&dnsConfig.server[retries % dnsConfig.namecount]);
    }
    if(resolver->query(host, [=](int error) {
        HOOK_BPF(resolver, error);
        //resolver由pending自持，全部子查询结束后自毁
        const Dns_Rcd& cached = rcd_cache.try_emplace(host).first->second;
        std::list<sockaddr_storage> addrs;
        uint32_t ttl = 0xefffffff;
        if(flags & QARES) {
            addrs = cached.a.addrs;
            ttl = cached.a.ttl;
        }
        if(flags & QAAAARES) {
            if(opt.ipv6_prefer) {
                addrs.insert(addrs.begin(), cached.aaaa.addrs.begin(), cached.aaaa.addrs.end());
            } else {
                addrs.insert(addrs.end(), cached.aaaa.addrs.begin(), cached.aaaa.addrs.end());
            }
            ttl = std::min(ttl, cached.aaaa.ttl);
        }
        if(error == 0 || !addrs.empty()){
            return func(Host_Result{.param = std::move(param),
                                    .addrs = rcdfilter(resolver->host, addrs),
                                    .ttl = ttl,
                                    .ech = cached.get_ech(),});
        }
        if(error == ns_r_nxdomain) {
            return func(Host_Result{.param = std::move(param), .error = error});
        }
        query_host_real(retries + 1, resolver->host, func, param, flags);
    }, qflags) < 0){
        delete resolver;
        return func(Host_Result{.param = std::move(param), .error = ns_r_servfail});
    }
}

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param, uint32_t flags) {
    HOOK_BPF(host, flags);
    if (flags == 0) {
        flags = QARES | QAAAARES | QECHRES;
    }
    sockaddr_storage addr{};
    if(storage_aton(host, 0, &addr) == 1){
        return func(Host_Result{.param = std::move(param), .addrs = {addr}, .ttl = 0xefffffff});
    }

    if (hosts.count(host)) {
        return func(Host_Result{.param = std::move(param), .addrs = rcdfilter(host, hosts[host]), .ttl = 0xefffffff});
    }

    if(!opt.ipv6_enabled) {
        flags &= ~QAAAARES;
    }
    if(opt.ech_mode == Disable) {
        flags &= ~QECHRES;
    }
    return query_host_real(0, host, func, param, flags);
}
#pragma GCC diagnostic pop

void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param) {
    HOOK_BPF(host, type);
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
        reload_hosts();
    }

    ResolverBase* resolver = nullptr;
    if(dnsConfig.doh.hostname[0]) {
        resolver = new HttpResolver(dnsConfig.doh);
    }else{
        if (dnsConfig.namecount == 0) {
            LOGE("[DNS] can't get dns server\n");
            return func(param, nullptr, 0);
        }
        resolver = new RawResolver(dnsConfig.server[rand() % dnsConfig.namecount].addr);
    }
    if(resolver->query(host, type, [func, param, resolver](const char* data, size_t len){
        HOOK_BPF(resolver, std::span<const std::byte>((const std::byte*)data, len));
        defer([resolver]{delete resolver;});
        func(param, data, len);
    }) < 0){
        return func(param, nullptr, 0);
    }
}

void query_raw(const void *data, size_t len, DNSRAWCB func, std::shared_ptr<void> param) {
    HOOK_BPF(std::span<const std::byte>((const std::byte*)data, len));
    if(dnsConfig.namecount == 0) {
        getDnsConfig(&dnsConfig);
        reload_hosts();
    }
    ResolverBase* resolver = nullptr;
    if(dnsConfig.doh.hostname[0]) {
        resolver = new HttpResolver(dnsConfig.doh);
    }else {
        if (dnsConfig.namecount == 0) {
            LOGE("[DNS] can't get dns server\n");
            return func(param, nullptr, 0);
        }
        resolver = new RawResolver(dnsConfig.server[rand() % dnsConfig.namecount].addr);
    }
    if(resolver->query(data, len, [func, param, resolver](const char* data, size_t len){
        HOOK_BPF(resolver, std::span<const std::byte>((const std::byte*)data, len));
        defer([resolver]{delete resolver;});
        func(param, data, len);
    }) < 0){
        delete resolver;
        func(param, nullptr, 0);
    }
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

//ECH握手被拒后，用retry configs更新ech记录(len为0表示服务端已回退不支持ech)。
//地址部分可能已过期或不存在，ech知识可独立存在(地址子记录天然过期态)
void update_ech_cache(const char *hostname, const void* data, size_t len) {
    auto it = rcd_cache.find(hostname);
    if(it == rcd_cache.end()){
        if(!len) {
            return;
        }
        //GREASE连接被拒等场景下没有既有条目，服务端带回的retry configs同样值得入库
        it = rcd_cache.try_emplace(hostname).first;
    }
    it->second.ech.ttl = 300;
    it->second.ech.get_time = time(nullptr);
    if(len) {
        it->second.ech.config.assign((const char*)data, len);
        LOG("[DNS] ech config of %s updated by retry configs\n", hostname);
    }else{
        //服务端回退不支持ech(此时data为null)，负缓存一段时间
        it->second.ech.config.clear();
        LOG("[DNS] ech of %s disabled by server\n", hostname);
    }
}


void dump_dns(Dumper dp, void* param){
    dp(param, "======================================\n");
    dp(param, "Dns server:\n");
    for(size_t i = 0; i < dnsConfig.namecount; i++) {
        dp(param, "  %s, rtt: %.3fms\n", getaddrstring(&dnsConfig.server[i].addr), dnsConfig.server[i].rtt);
    }
    dp(param, "--------------------------------------\n");
    dp(param, "Dns cache:\n");
    for(const auto& i: rcd_cache){
        const Dns_Rcd& rcd = i.second;
        time_t now = time(nullptr);
        //A/AAAA/ech独立计时，分别展示剩余秒数；过期为-1，ech负缓存以[ech-]标记
        char echbuf[32] = "";
        if(rcd.ech.fresh()) {
            snprintf(echbuf, sizeof(echbuf), " [ech%s:%d]",
                     rcd.ech.config.empty() ? "-" : "",
                     (int)(rcd.ech.get_time + rcd.ech.ttl - now));
        }
        dp(param, "  %s: A:%d AAAA:%d%s\n", i.first.c_str(),
           rcd.a.fresh() ? (int)(rcd.a.get_time + rcd.a.ttl - now) : -1,
           rcd.aaaa.fresh() ? (int)(rcd.aaaa.get_time + rcd.aaaa.ttl - now) : -1,
           echbuf);
        if(rcd.a.fresh()) {
            for(const auto& j: rcdfilter(i.first, rcd.a.addrs)){
                dp(param, "    %s\n", getaddrstring(&j));
            }
        }
        if(rcd.aaaa.fresh()) {
            for(const auto& j: rcdfilter(i.first, rcd.aaaa.addrs)){
                dp(param, "    %s\n", getaddrstring(&j));
            }
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
