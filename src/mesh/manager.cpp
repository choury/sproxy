#include "mesh/manager.h"
#include "mesh/route.h"

#include "misc/config.h"
#include "misc/net.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "prot/dns/resolver.h"
#include "res/fetch.h"
#include "res/responser.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <random>
#include <sstream>

namespace {

constexpr uint32_t MESH_DEFAULT_MS      = 10'000;
constexpr uint32_t MESH_SYNC_DEFAULT_MS = 30'000;
constexpr uint32_t MESH_FIRST_DELAY_MS  = 1'000;
constexpr size_t   MESH_SYNC_BODY_MAX   = 1024 * 1024; //与 http_fetch 接收上限一致

MeshManager* instance = nullptr;
std::mt19937 rng{static_cast<uint32_t>(getutime())};

uint64_t now_ms() {
    return getutime() / 1000;
}

//±10% 抖动：全网轮次错相，避免同相位探测脉冲
uint32_t jitter_ms(uint32_t ms) {
    return ms * (90 + rng() % 21) / 100;
}

uint32_t env_interval(const char* name, uint32_t def) {
    const char* s = getenv(name);
    if(!s || !*s) {
        return def;
    }
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if(end == s || *end != '\0' || v < 1 || v > 3600) {
        LOGE("[mesh] ignore bad %s=%s\n", name, s);
        return def;
    }
    return (uint32_t)v * 1000;
}

template<typename C>
std::string join_str(const C& v, char sep) {
    std::string out;
    for(const auto& s : v) {
        if(!out.empty()) {
            out += sep;
        }
        out += s;
    }
    return out;
}

//宣告地址限定 https/http/quic，其余按坏地址丢弃；
//protocol 由 scheme 推出，连接层据此选传输
bool mesh_parse_addr(const char* addr, Addr* a) {
    if(splitAddr(addr, a, nullptr)) {
        return false;
    }
    if(strcasecmp(a->scheme, "https") == 0) {
        strcpy(a->scheme, "https");
        strcpy(a->protocol, "ssl");
        a->port = a->port?:443;
    }else if(strcasecmp(a->scheme, "http") == 0) {
        strcpy(a->scheme, "http");
        strcpy(a->protocol, "tcp");
        a->port = a->port?:80;
    }else if(strcasecmp(a->scheme, "quic") == 0) {
        strcpy(a->scheme, "quic");
        strcpy(a->protocol, "quic");
        a->port = a->port?:443;
    }else{
        return false;
    }
    return true;
}

std::string caps_str(uint32_t caps) {
    std::string s;
    if(caps & MESH_CAP_RELAY) {
        s += " relay";
    }
    if(caps & MESH_CAP_EXIT) {
        s += " exit";
    }
    return s.empty() ? " -" : s;
}

} //namespace

std::set<std::string> MeshEntry::addrs() const {
    std::set<std::string> addrs;
    for(const auto& [addr, endpoint] : endpoints) {
        addrs.insert(addr);
    }
    return addrs;
}

//宣告地址集变化：增删对应 endpoint，存活地址的线路与解析状态原样保留
void MeshEntry::setAddrs(const std::set<std::string>& addrs) {
    for(auto it = endpoints.begin(); it != endpoints.end();) {
        if(addrs.count(it->first)) {
            ++it;
        }else{
            it = endpoints.erase(it);
        }
    }
    for(const auto& addr : addrs) {
        auto endpoint = std::make_shared<MeshEndpoint>();
        //坏宣告地址：addr 留空，不解析不产线路
        Addr a{};
        if(mesh_parse_addr(addr.c_str(), &a)) {
            endpoint->addr = a;
        }
        endpoints.emplace(addr, std::move(endpoint));
    }
}

//调用方以 cost()>0 保证有活跃线路
Destination MeshEntry::activeDest() const {
    std::shared_ptr<MeshEndpoint> endpoint = active.lock();
    std::shared_ptr<MeshPath> live = endpoint->active.lock();
    return live->getDest(endpoint->addr);
}

//线路+探测状态：addr|ip (12.3ms*)，*=活跃线路；未解析时退回展示宣告地址
std::string MeshEntry::probeState() const {
    std::string s;
    for(const auto& [addr, endpoint] : endpoints) {
        if(endpoint->paths.empty()) {
            if(!s.empty()) {
                s += ' ';
            }
            s += addr;
            s += " (new)";
            continue;
        }
        for(const auto& path : endpoint->paths) {
            if(!s.empty()) {
                s += ' ';
            }
            s += addr;
            s += '|';
            s += getaddrstring(&path->ip);
            s += " (";
            if(path->rtt > 0) {
                char one[32];
                snprintf(one, sizeof(one), "%.1fms", path->rtt);
                s += one;
            } else if(path->fails > 0) {
                s += "fail" + std::to_string(path->fails);
            } else {
                s += "new";
            }
            if(endpoint->active.lock() == path) {
                s += '*';
            }
            s += ')';
        }
    }
    return s;
}

void MeshManager::Start() {
    if(instance) {
        return;
    }
    assert(opt.mesh_name);
    instance = new MeshManager();
    LOG("[mesh] started as %s%s addrs=[%s]\n", opt.mesh_name, caps_str(opt.mesh_caps).c_str(),
        join_str(instance->self_addrs, ' ').c_str());
}

MeshManager* MeshManager::GetInstance() {
    return instance;
}

MeshManager::MeshManager() {
    strcpy(mesh_credit.user, "mesh");
    strncpy(mesh_credit.pass, opt.mesh_secret, sizeof(mesh_credit.pass) - 1);
    for(struct bind_list* n = opt.listen_list; n; n = n->next) {
        const struct BindInfo& info = n->info;
        if(!info.port) {
            continue;
        }
        const char* scheme = nullptr;
        if(strcmp(info.protocol, "ssl") == 0) {
            scheme = "https";
        } else if(strcmp(info.protocol, "quic") == 0) {
            scheme = "quic";
        } else if(strcmp(info.protocol, "http") == 0 && !opt.redirect_http) {
            //redirect-http 下 http 监听只回 308，不能承载 mesh 流量
            scheme = "http";
        }
        if(!scheme) {
            continue;
        }
        char addr[DOMAINLIMIT + 32];
        snprintf(addr, sizeof(addr), "%s://%s:%u", scheme, opt.mesh_name, info.port);
        self_addrs.emplace_back(addr);
    }
    for(struct arg_list* p = opt.mesh_peers; p; p = p->next) {
        Addr dest{};
        if(!mesh_parse_addr(p->arg, &dest)) {
            LOGE("[mesh] bad mesh-peer: %s\n", p->arg);
            continue;
        }
        char addr[DOMAINLIMIT + 32];
        snprintf(addr, sizeof(addr), "%s://%s:%u", dest.scheme, dest.hostname, dest.port);
        std::shared_ptr<MeshEntry>& entry = table[dest.hostname];
        if(!entry) {
            entry = std::make_shared<MeshEntry>();
        }
        entry->seeded = true;
        //种子能力位未知，按可探测假设；收到宣告后覆盖
        entry->caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        //ts 恒 0：种子是本机假设而非对端宣告，须输给任何通过时钟偏差检查的宣告
        auto endpoint = std::make_shared<MeshEndpoint>();
        endpoint->addr = dest;
        entry->endpoints.emplace(addr, std::move(endpoint)); //同节点多种子并存
    }
    probe_ms = env_interval("SPROXY_MESH_PROBE_INTERVAL", MESH_DEFAULT_MS);
    sync_ms = env_interval("SPROXY_MESH_SYNC_INTERVAL", MESH_SYNC_DEFAULT_MS);
    //首轮 0.5~1.5s 随机延迟快速收敛；job 不会自动重复，两个 round 末尾各自 UpdateJob 自续
    probe_job = AddJob([this]{ probe_round(); }, MESH_FIRST_DELAY_MS / 2 + rng() % MESH_FIRST_DELAY_MS, 0);
    sync_job = AddJob([this]{ sync_round(); }, MESH_FIRST_DELAY_MS / 2 + rng() % MESH_FIRST_DELAY_MS, 0);
}

void MeshManager::probe_path(const std::shared_ptr<MeshEndpoint>& endpoint,
                             const std::shared_ptr<MeshPath>& lp) {
    auto now = now_ms();
    if(now < lp->next_try) {
        return;
    }
    //到期取 0.8 周期：轮次间隔带 ±10% 抖动，取整周期会被高侧轮次擦边错过而白等一轮
    lp->next_try = now + probe_ms * 8 / 10;
    char buff[HEADLENLIMIT];
    int headlen = snprintf(buff, sizeof(buff), "GET localhost:%d/mesh/ping HTTP/1.1" CRLF CRLF, endpoint->addr.port);
    auto req = UnpackHttpReq(buff, headlen);
    req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
    uint64_t t0 = getutime();
    uint32_t timeout = std::max(500u, std::min(5000u, probe_ms / 2));
    //endpoint/线路均以 weak 入闭包：被删后随引用释放，回调凭 lock 感知；
    //线路对象只被所属 endpoint 强持有，path 存活即 endpoint 存活
    http_fetch(std::move(req), lp->getDest(endpoint->addr), "",
               [probe_ms = probe_ms, t0, wep = std::weak_ptr<MeshEndpoint>(endpoint),
                wp = std::weak_ptr<MeshPath>(lp)](std::shared_ptr<HttpResHeader> res, std::string) {
        std::shared_ptr<MeshPath> path = wp.lock();
        if(!path) {
            return; //宣告/DNS 变化或条目过期可能已清掉该线路
        }
        std::shared_ptr<MeshEndpoint> endpoint = wep.lock();
        if(endpoint->active.lock() != path) {
            path->next_try = now_ms() + MESH_PATH_REFRESH_MS;
        }
        if(res && atoi(res->status) == 200) {
            double rtt = (getutime() - t0) / 1000.0;
            LOGD(DMESH, "probe ok %s %.1fms\n", getaddrstring(&path->ip), rtt);
            path->rtt = rtt;
            path->fails = 0;
            path->backoff = 0;
            return;
        }
        path->fails++;
        LOGD(DMESH, "probe fail %s (%s)\n", getaddrstring(&path->ip),
                res ? res->status : "no response");
        if(path->fails >= MESH_FAIL_DEAD) {
            path->rtt = 0;
            path->backoff = mesh_next_backoff(path->backoff, probe_ms);
            path->next_try = now_ms() + path->backoff;
            if(endpoint->active.lock() == path) {
                endpoint->active.reset();
            }
        }
    }, timeout);
}

void MeshManager::dns_cb(const Host_Result& result) {
    MeshManager* manager = GetInstance();
    const MeshDnsReq& req = *std::static_pointer_cast<MeshDnsReq>(result.param);
    std::shared_ptr<MeshEndpoint> endpoint = req.endpoint.lock();
    if(!endpoint) {
        return; //条目或 endpoint 可能已在解析期间被擦除
    }
    if(result.error || result.addrs.empty()) {
        //解析失败保留旧线路表，下轮重试
        endpoint->dns_retry = now_ms() + manager->probe_ms;
        return;
    }
    //按解析结果重建线路表：同 IP 沿用原对象，探测历史与活跃/在途 weak 引用随之保留
    std::vector<std::shared_ptr<MeshPath>> next;
    for(const auto& sa : result.addrs) {
        const std::string ipstr = getaddrstring(&sa);
        std::shared_ptr<MeshPath> path;
        for(auto& op : endpoint->paths) {
            if(getaddrstring(&op->ip) == ipstr) {
                path = op;
                break;
            }
        }
        if(!path) {
            path = std::make_shared<MeshPath>();
            path->ip = sa;
            ((sockaddr_in6*)&path->ip)->sin6_port = htons(endpoint->addr.port);
        }
        next.push_back(std::move(path));
    }
    endpoint->paths = std::move(next);
    uint64_t ttl = result.ttl * 1000ull;
    endpoint->dns_retry = now_ms() + std::clamp<uint64_t>(ttl, manager->probe_ms, MESH_DNS_RETRY_MAX_MS);
}

void MeshManager::probe_round() {
    uint64_t now = now_ms();
    for(auto it = table.begin(); it != table.end();) {
        if(!it->second->seeded && now > it->second->ts + MESH_FRESHNESS_MS) {
            it = table.erase(it);
            continue;
        }
        ++it;
    }
    for(auto& [_, entry] : table) {
        for(auto& [addr, endpoint] : entry->endpoints) {
            if(now < endpoint->dns_retry || !endpoint->addr.hostname[0]) {
                continue;
            }
            //先占位防重复发起(解析器内部重试可长达 ~15s)，回调按真实 ttl 修正
            endpoint->dns_retry = now + std::max<uint64_t>(probe_ms, 30'000);
            auto req = std::make_shared<MeshDnsReq>(MeshDnsReq{endpoint, endpoint->addr.hostname});
            query_host(req->host.c_str(), dns_cb, req);
        }
        //驱动活跃线路重算：未选/失效立即重选，命中缓存时零开销
        for(auto& [addr, endpoint] : entry->endpoints) {
            endpoint->activePath();
            for(auto& path : endpoint->paths) {
                probe_path(endpoint, path); //next_try 到期的才会真正发出
            }
        }
    }
    probe_job = UpdateJob(std::move(probe_job), [this]{ probe_round(); }, jitter_ms(probe_ms));
}

void MeshManager::sync_round() {
    for(auto& [name, entry] : table) {
        if(entry->syncing) {
            continue;
        }
        //cost()=0 即无活跃线路，不同步：死节点不白打 POST，可达性由探测退避维护
        if(entry->cost() == 0) {
            continue;
        }
        Destination dest = entry->activeDest();
        entry->syncing = true;
        char buff[HEADLENLIMIT];
        int headlen = snprintf(buff, sizeof(buff), "POST localhost:%d/mesh/nodes HTTP/1.1" CRLF CRLF, dest.addr.port);
        auto req = UnpackHttpReq(buff, headlen);
        req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
        uint32_t timeout = std::max(2000u, std::min(10'000u, sync_ms));
        http_fetch(std::move(req), dest, serialize(),
                   [this, addr = dest.addr, we = std::weak_ptr<MeshEntry>(entry)](std::shared_ptr<HttpResHeader> res, std::string body) {
            std::shared_ptr<MeshEntry> entry = we.lock();
            if(!entry) {
                return; //merge 可能已擦除本条目(对端自宣 caps=0 降级为纯入口)
            }
            entry->syncing = false;
            if(!res || atoi(res->status) != 200) {
                LOGD(DMESH, "sync to %s failed: %s\n", dumpAddr(addr).c_str(), res ? res->status : "no response");
                return;
            }
            merge(body);
        }, timeout);
    }
    sync_job = UpdateJob(std::move(sync_job), [this]{ sync_round(); }, jitter_ms(sync_ms));
}

//每节点一行：N <名> <能力位> <ts> <addr|addr...|-> [对端=边权 ...]
//宣告与邻边同轮同 ts 携带，空边集显式表达(缺席轮内即为清空)
std::string MeshManager::serialize() const {
    std::ostringstream out;
    out << "N " << opt.mesh_name << " " << opt.mesh_caps << " " << now_ms() << " "
        << (self_addrs.empty() ? "-" : join_str(self_addrs, '|'));
    for(const auto& [name, entry] : table) {
        if(entry->cost() > 0) {
            out << " " << name << "=" << entry->cost();
        }
    }
    out << "\n";
    for(const auto& [name, entry] : table) {
        std::set<std::string> addrs = entry->addrs();
        out << "N " << name << " " << entry->caps << " " << entry->ts << " "
            << (addrs.empty() ? "-" : join_str(addrs, '|'));
        for(const auto& [peer, cost] : entry->edges) {
            out << " " << peer << "=" << cost;
        }
        out << "\n";
    }
    //本机 rproxy 后端经常驻会话可达，宣告为出口；无直连地址，边权取固定占位值。
    if(opt.mesh_caps & MESH_CAP_RELAY) {
        uint64_t now = now_ms();
        for(const auto& [name, r] : rproxys) {
            if(name == opt.mesh_name) {
                continue;
            }
            out << "N " << name << " " << MESH_CAP_EXIT << " " << now << " - "
                << opt.mesh_name << "=" << MESH_RPROXY_RTT_MS << "\n";
        }
    }
    return out.str();
}

void MeshManager::merge(const std::string& body) {
    uint64_t now = now_ms();
    std::istringstream iss(body);
    std::string line;
    while(std::getline(iss, line)) {
        std::istringstream ls(line);
        std::string tag;
        ls >> tag;
        if(tag != "N") {
            continue;
        }
        std::string name, addrstr;
        uint32_t caps = 0;
        uint64_t ts = 0;
        if(!(ls >> name >> caps >> ts >> addrstr)) {
            continue;
        }
        if(name == opt.mesh_name || rproxys.count(name)) {
            continue;
        }
        //时钟偏差超窗：静默拒收
        if(ts > now + MESH_FRESHNESS_MS || now > ts + MESH_FRESHNESS_MS) {
            LOGD(DMESH, "drop stale entry %s (ts drift)\n", name.c_str());
            continue;
        }
        //纯入口节点不入地址簿：收到其行即清除既有条目，能力降级即时生效
        if(caps == 0) {
            if(table.erase(name) != 0) {
                LOGD(DMESH, "erase ingress entry %s\n", name.c_str());
            }
            continue;
        }
        std::set<std::string> addrs;
        if(addrstr != "-") {
            std::istringstream as(addrstr);
            std::string addr;
            while(std::getline(as, addr, '|')) {
                if(!addr.empty()) {
                    addrs.insert(addr);
                }
            }
        }
        std::map<std::string, double> edges;
        std::string pair;
        while(ls >> pair) {
            auto pos = pair.rfind('=');
            if(pos == std::string::npos) {
                continue;
            }
            double cost = strtod(pair.c_str() + pos + 1, nullptr);
            if(cost > 0) {
                edges[pair.substr(0, pos)] = cost;
            }
        }
        auto it = table.find(name);
        if(it == table.end()) {
            auto entry = std::make_shared<MeshEntry>();
            entry->caps = caps;
            entry->ts = ts;
            entry->setAddrs(addrs);
            entry->edges = std::move(edges);
            table.emplace(name, std::move(entry));
            LOGD(DMESH, "discovered %s addrs=[%s]\n", name.c_str(), join_str(addrs, ' ').c_str());
            continue;
        }
        MeshEntry& entry = *it->second;
        std::set<std::string> mine = entry.addrs();
        if(ts < entry.ts) {
            continue;
        }
        if(mine != addrs && !entry.seeded) {
            LOGE("[mesh] %s changed addrs [%s] -> [%s], keep local\n", name.c_str(),
                    join_str(mine, ' ').c_str(), join_str(addrs, ' ').c_str());
            continue;
        }
        entry.seeded = false;
        entry.caps = caps;
        entry.edges = std::move(edges);
        entry.ts = ts;
        if(mine != addrs) {
            entry.setAddrs(addrs);
            //种子让位与常规刷新同路：宣告地址集变化时线路表随之重建
            LOGD(DMESH, "%s changed addrs [%s] -> [%s]\n", name.c_str(),
                    join_str(mine, ' ').c_str(), join_str(addrs, ' ').c_str());
        }
    }
}

strategy MeshManager::Route(const std::string& target, Destination* dest) {
    MeshManager* manager = GetInstance();
    if(!manager) {
        return strategy{Strategy::none, ""};
    }
    if(target == opt.mesh_name) {
        if(opt.mesh_caps & MESH_CAP_EXIT) {
            return strategy{Strategy::direct, ""};
        }
        return strategy{Strategy::proxy, "[[mesh: no exit]]\n"};
    }
    MeshRoutePath path;
    std::string exit_name = target;
    if(target == "auto") {
        if(!mesh_pick_exit(opt.mesh_name, manager->table, exit_name, path)) {
            manager->last_auto_exit = "-";
            return strategy{Strategy::proxy, "[[mesh: no exit]]\n"};
        }
        manager->last_auto_exit = exit_name;
    }else{
        auto it = manager->table.find(exit_name);
        if(it == manager->table.end() || !it->second->fresh(now_ms())) {
            return strategy{Strategy::none, ""};
        }
        if(!(it->second->caps & MESH_CAP_EXIT)) {
            return strategy{Strategy::proxy, "[[mesh: no exit]]\n"};
        }
        if(!mesh_route(opt.mesh_name, manager->table, exit_name, path)) {
            return strategy{Strategy::proxy, "[[mesh: no route]]\n"};
        }
    }
    //用活跃线路连首跳，挂逐跳凭据(identifier=最终目标)
    *dest = manager->table.at(path.first_hop)->activeDest();
    dest->credit = manager->mesh_credit;
    strncpy(dest->credit.identifier, exit_name.c_str(), sizeof(dest->credit.identifier) - 1);
    return strategy{Strategy::proxy, ""};
}

void MeshManager::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    uint64_t id = req->request_id;
    //file.cpp 已保证前缀 "mesh/"
    std::string endpoint = req->filename.substr(5);
    //控制面仅收 mesh 用户凭据
    if(!checkmesh(&req->cr)) {
        auto sheader = HttpResHeader::create(S401, sizeof(S401), id);
        sheader->set("WWW-Authenticate", "Basic realm=\"mesh\"");
        return response(rw, sheader, "[[Authorization needed]]\n");
    }
    if(endpoint == "ping") {
        return response(rw, HttpResHeader::create(S200, sizeof(S200), id), "pong\n");
    }
    if(endpoint == "nodes" && req->ismethod("POST")) {
        //POST 即同步：body 为对端视图，合并后应答自身视图
        auto cb = IRWerCallback::create()
            ->onError([this, id](int, int) {
                //回调来自 RWer 内部，延迟一拍清理避免重入
                addjob_with_name([this, id]{ sync_reqs.erase(id); }, "mesh_sync_clean", 0, JOB_FLAGS_AUTORELEASE);
            })->onClose([this, id] {
                sync_reqs.erase(id);
            })->onRead([this, id](Buffer&& bb) -> size_t {
                auto it = sync_reqs.find(id);
                if(it == sync_reqs.end()) {
                    return bb.len;
                }
                if(bb.len == 0) {
                    std::string body = std::move(it->second.data);
                    std::shared_ptr<MemRWer> lrw = it->second.rw;
                    sync_reqs.erase(it);
                    merge(body);
                    response(lrw, HttpResHeader::create(S200, sizeof(S200), id), serialize());
                    return 0;
                }
                if(it->second.data.size() + bb.len > MESH_SYNC_BODY_MAX) {
                    std::shared_ptr<MemRWer> lrw = it->second.rw;
                    sync_reqs.erase(it);
                    response(lrw, HttpResHeader::create(S413, sizeof(S413), id), "[[payload too large]]\n");
                    return bb.len;
                }
                it->second.data.append((const char*)bb.data(), bb.len);
                return bb.len;
            });
        sync_reqs[id] = SyncStatus{req, rw, cb, ""};
        rw->SetCallback(cb);
        return;
    }
    return response(rw, HttpResHeader::create(S404, sizeof(S404), id), "[[not found]]\n");
}

void MeshManager::dump(Dumper dp, void* param) {
    uint64_t now = now_ms();
    dp(param, "mesh: node=%s caps:%s probe=%us sync=%us entries=%zu\n",
       opt.mesh_name, caps_str(opt.mesh_caps).c_str(),
       probe_ms / 1000, sync_ms / 1000, table.size());
    dp(param, "node table:\n");
    for(const auto& [name, entry] : table) {
        char cost[32], updated[32];
        snprintf(cost, sizeof(cost), "%.1fms", entry->cost());
        snprintf(updated, sizeof(updated), "%.1fs", (now - entry->ts) / 1000.0);
        dp(param, "  %s %s caps:%s cost=%s updated=%s%s\n",
           name.c_str(), entry->probeState().c_str(), caps_str(entry->caps).c_str(),
           entry->cost() > 0 ? cost : "-",
           entry->ts ? updated : "-",
           entry->seeded ? " seeded" : "");
    }
    dp(param, "auto exit: %s\n", last_auto_exit.empty() ? "-" : last_auto_exit.c_str());
    if(opt.mesh_caps & MESH_CAP_RELAY) {
        std::string s;
        for(const auto& [name, r] : rproxys) {
            s += " " + name;
        }
        if(!s.empty()) {
            dp(param, "rproxy exits:%s\n", s.c_str());
        }
    }
    dp(param, "link states:\n");
    auto dump_edges = [&](const std::string& who, const std::map<std::string, double>& edges) {
        std::string es;
        for(const auto& [peer, cost] : edges) {
            es += " " + peer + "@" + std::to_string(cost).substr(0, 5) + "ms";
        }
        dp(param, "  %s:%s\n", who.c_str(), es.c_str());
    };
    std::map<std::string, double> mine;
    for(const auto& [name, entry] : table) {
        if(entry->cost() > 0) {
            mine.emplace(name, entry->cost());
        }
    }
    dump_edges(opt.mesh_name, mine);
    for(const auto& [name, entry] : table) {
        if(!entry->edges.empty()) {
            dump_edges(name, entry->edges);
        }
    }
    dp(param, "routes:\n");
    for(const auto& [name, entry] : table) {
        if(!entry->fresh(now) || !(entry->caps & MESH_CAP_EXIT)) {
            continue;
        }
        MeshRoutePath path;
        if(mesh_route(opt.mesh_name, table, name, path)) {
            dp(param, "  %s via %s cost=%.1fms hops=%d\n",
               name.c_str(), path.first_hop.c_str(), path.cost, path.hops);
        } else {
            dp(param, "  %s unreachable\n", name.c_str());
        }
    }
}

void dump_mesh(Dumper dp, void* param) {
    if(MeshManager* manager = MeshManager::GetInstance()) {
        manager->dump(dp, param);
    }
}
