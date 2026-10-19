#include "mesh/manager.h"
#include "mesh/route.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "prot/dns/resolver.h"
#include "res/fetch.h"
#include "res/responser.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
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

//线路+探测状态：addr|ip (12.3ms*)，*=活跃线路；未解析时退回展示宣告地址
std::string probe_state_str(const MeshEntry& e) {
    std::string s;
    if(e.paths.empty()) {
        for(const auto& addr : e.addrs) {
            if(!s.empty()) {
                s += ' ';
            }
            s += addr;
            s += " (new)";
        }
        return s;
    }
    for(const auto& [key, path] : e.paths) {
        if(!s.empty()) {
            s += ' ';
        }
        s += key;
        s += " (";
        if(path.rtt > 0) {
            char one[32];
            snprintf(one, sizeof(one), "%.1fms", path.rtt);
            s += one;
        } else if(path.fails > 0) {
            s += "fail" + std::to_string(path.fails);
        } else {
            s += "new";
        }
        if(key == e.active) {
            s += '*';
        }
        s += ')';
    }
    return s;
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
        Destination dest{};
        if(parseDest(p->arg, &dest) || !dest.addr.port) {
            LOGE("[mesh] bad mesh-peer: %s\n", p->arg);
            continue;
        }
        //dumpAddr 会把 quic 的 scheme 序列化成 https，须按 protocol 还原，
        //否则 quic-only 节点的种子探测走了 TCP+TLS
        const char* scheme = strcmp(dest.addr.protocol, "quic") == 0 ? "quic"
                           : strcmp(dest.addr.protocol, "ssl") == 0 ? "https" : "http";
        char addr[DOMAINLIMIT + 32];
        snprintf(addr, sizeof(addr), "%s://%s:%u", scheme, dest.addr.hostname, dest.addr.port);
        MeshEntry& e = table[dest.addr.hostname];
        e.seeded = true;
        //种子能力位未知，按可探测假设；收到宣告后覆盖
        e.caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        //ts 恒 0：种子是本机假设而非对端宣告，须输给任何通过时钟偏差检查的宣告
        e.addrs.insert(addr);
    }
    probe_ms = env_interval("SPROXY_MESH_PROBE_INTERVAL", MESH_DEFAULT_MS);
    sync_ms = env_interval("SPROXY_MESH_SYNC_INTERVAL", MESH_SYNC_DEFAULT_MS);
    //首轮 0.5~1.5s 随机延迟快速收敛；job 不会自动重复，两个 round 末尾各自 UpdateJob 自续
    probe_job = AddJob([this]{ probe_round(); }, MESH_FIRST_DELAY_MS / 2 + rng() % MESH_FIRST_DELAY_MS, 0);
    sync_job = AddJob([this]{ sync_round(); }, MESH_FIRST_DELAY_MS / 2 + rng() % MESH_FIRST_DELAY_MS, 0);
}

bool MeshManager::pick_conn(const MeshEntry& e, Destination* dest) const {
    const AddrProbe* path = mesh_alive_path(e);
    if(!path) {
        return false;
    }
    *dest = mesh_path_dest(*path);
    return true;
}

void MeshManager::probe_path(const std::string& node, const std::string& key, AddrProbe& lp) {
    //到期取 0.8 周期：轮次间隔带 ±10% 抖动，取整周期会被高侧轮次擦边错过而白等一轮
    lp.next_try = now_ms() + probe_ms * 8 / 10;
    char buff[HEADLENLIMIT];
    int headlen = snprintf(buff, sizeof(buff), "GET localhost:%d/mesh/ping HTTP/1.1" CRLF CRLF, lp.addr.port);
    auto req = UnpackHttpReq(buff, headlen);
    req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
    uint64_t t0 = getutime();
    uint32_t timeout = std::max(500u, std::min(5000u, probe_ms / 2));
    http_fetch(std::move(req), mesh_path_dest(lp), "", [this, node, key, t0](std::shared_ptr<HttpResHeader> res, std::string) {
        auto it = table.find(node);
        if(it == table.end()) {
            return;
        }
        MeshEntry& e = it->second;
        auto path = e.paths.find(key);
        if(path == e.paths.end()) {
            return; //宣告/DNS 变化可能已清掉该线路
        }
        if(res && atoi(res->status) == 200) {
            e.ok++;
            double rtt = (getutime() - t0) / 1000.0;
            LOGD(DMESH, "probe %s ok %s %.1fms\n", node.c_str(), key.c_str(), rtt);
            AddrProbe& lp = path->second;
            lp.rtt = rtt;
            lp.fails = 0;
            lp.backoff = 0;
            if(e.active != key) {
                //在值缺失(未选定或被重建删掉)时直接上位；否则须优于在值超过滞回带
                auto act = e.paths.find(e.active);
                if(act == e.paths.end() || rtt + MESH_SWITCH_MARGIN_MS < act->second.rtt) {
                    LOGD(DMESH, "active path -> %s (%.1fms)\n", key.c_str(), rtt);
                    e.active = key;
                }
            }
        } else {
            e.fail++;
            LOGD(DMESH, "probe %s fail %s (%s)\n", node.c_str(), key.c_str(),
                 res ? res->status : "no response");
            note_fail(e, key);
        }
        e.cost = mesh_edge_cost(e);
    }, timeout);
}

void MeshManager::note_fail(MeshEntry& e, const std::string& key) {
    auto path = e.paths.find(key);
    if(path == e.paths.end()) {
        return;
    }
    AddrProbe& lp = path->second;
    lp.fails++;
    if(lp.fails < MESH_FAIL_DEAD) {
        return;
    }
    lp.backoff = mesh_next_backoff(lp.backoff, probe_ms);
    lp.next_try = now_ms() + lp.backoff;
    if(e.active == key) {
        //活跃线路判死：全量重选，退避值保留供梯子续算
        mesh_failover(e);
    }
}

void MeshManager::dns_cb(const Host_Result& result) {
    MeshManager* m = GetInstance();
    if(!m) {
        return;
    }
    const std::string& node = *std::static_pointer_cast<std::string>(result.param);
    auto it = m->table.find(node);
    if(it == m->table.end()) {
        return;
    }
    MeshEntry& e = it->second;
    if(result.error || result.addrs.empty()) {
        //解析失败保留旧线路表，下轮重试
        e.dns_retry = now_ms() + m->probe_ms;
        return;
    }
    e.ips.assign(result.addrs.begin(), result.addrs.end());
    mesh_rebuild_paths(e);
    uint64_t ttl = result.ttl * 1000ull;
    e.dns_retry = now_ms() + std::clamp<uint64_t>(ttl, m->probe_ms, MESH_DNS_RETRY_MAX_MS);
    if(!e.active.empty()) {
        return;
    }
    //未选定线路：新解析出的未探测线路立即探测，加快收敛
    for(auto& [key, path] : e.paths) {
        if(path.next_try == 0) {
            m->probe_path(node, key, path);
        }
    }
}

void MeshManager::probe_round() {
    uint64_t now = now_ms();
    for(auto it = table.begin(); it != table.end();) {
        MeshEntry& e = it->second;
        if(!e.seeded && now > e.ts + MESH_FRESHNESS_MS) {
            it = table.erase(it);
            continue;
        }
        ++it;
    }
    for(auto& [name, e] : table) {
        if(now >= e.dns_retry && !e.addrs.empty()) {
            //先占位防重复发起(解析器内部重试可长达 ~15s)，回调按真实 ttl 修正
            e.dns_retry = now + std::max<uint64_t>(probe_ms, 30'000);
            //名字拷贝随 param 存活：解析器异步持有 host 裸指针，表键可能在解析期间被擦除
            auto req = std::make_shared<std::string>(name);
            query_host(req->c_str(), dns_cb, req);
        }
        if(e.active.empty()) {
            for(auto& [key, path] : e.paths) {
                if(now >= path.next_try) {
                    probe_path(name, key, path);
                }
            }
        } else {
            auto path = e.paths.find(e.active);
            if(path != e.paths.end() && now >= path->second.next_try) {
                probe_path(name, e.active, path->second);
            }
        }
    }
    probe_job = UpdateJob(std::move(probe_job), [this]{ probe_round(); }, jitter_ms(probe_ms));
}

void MeshManager::sync_round() {
    for(auto& [name, e] : table) {
        if(e.syncing || e.addrs.empty()) {
            continue;
        }
        //cost=0 即无活跃线路，不同步：死节点不白打 POST，可达性由探测退避维护
        if(e.cost == 0) {
            continue;
        }
        Destination dest{};
        //回调远晚于本轮迭代执行，结构化绑定按 C++17 语义不能进闭包
        const std::string node = name;
        const std::string key = e.active;
        if(!pick_conn(e, &dest)) {
            continue;
        }
        e.syncing = true;
        char buff[HEADLENLIMIT];
        int headlen = snprintf(buff, sizeof(buff), "POST localhost:%d/mesh/nodes HTTP/1.1" CRLF CRLF, dest.addr.port);
        auto req = UnpackHttpReq(buff, headlen);
        req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
        uint32_t timeout = std::max(2000u, std::min(10'000u, sync_ms));
        http_fetch(std::move(req), dest, serialize(),
                   [this, node, key](std::shared_ptr<HttpResHeader> res, std::string body) {
            auto it = table.find(node);
            if(it == table.end()) {
                return;
            }
            MeshEntry& e = it->second;
            e.syncing = false;
            if(!res || atoi(res->status) != 200) {
                LOGD(DMESH, "sync %s failed: %s\n", node.c_str(), res ? res->status : "no response");
                note_fail(e, key);
                e.cost = mesh_edge_cost(e);
                return;
            }
            merge(body);
            //merge 可能擦除本条目(对端自宣 caps=0 降级为纯入口)，须重新定位
            auto it2 = table.find(node);
            if(it2 != table.end()) {
                it2->second.cost = mesh_edge_cost(it2->second);
            }
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
    for(const auto& [name, e] : table) {
        if(e.cost > 0) {
            out << " " << name << "=" << e.cost;
        }
    }
    out << "\n";
    for(const auto& [name, e] : table) {
        out << "N " << name << " " << e.caps << " " << e.ts << " "
            << (e.addrs.empty() ? "-" : join_str(e.addrs, '|'));
        for(const auto& [peer, cost] : e.edges) {
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
            MeshEntry e;
            e.caps = caps;
            e.ts = ts;
            e.addrs = addrs;
            e.edges = std::move(edges);
            table.emplace(name, std::move(e));
            LOGD(DMESH, "discovered %s addrs=[%s]\n", name.c_str(), join_str(addrs, ' ').c_str());
        } else if(it->second.addrs != addrs && !it->second.seeded) {
            LOGE("[mesh] %s changed addrs [%s] -> [%s], keep local\n", name.c_str(),
                 join_str(it->second.addrs, ' ').c_str(), join_str(addrs, ' ').c_str());
        } else if(ts < it->second.ts) {
            //多径转发下旧轮次乱序到达，整行丢弃防回退
            continue;
        } else {
            //种子让位与常规刷新同路：宣告地址集变化时线路表随之重建
            it->second.seeded = false;
            if(it->second.addrs != addrs) {
                LOGD(DMESH, "%s changed addrs [%s] -> [%s]\n", name.c_str(),
                     join_str(it->second.addrs, ' ').c_str(), join_str(addrs, ' ').c_str());
                it->second.addrs = addrs;
                mesh_rebuild_paths(it->second);
            }
            it->second.caps = caps;
            it->second.ts = ts;
            it->second.edges = std::move(edges);
        }
    }
}

strategy MeshManager::Route(const std::string& target, Destination* dest) {
    MeshManager* m = GetInstance();
    if(!m) {
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
        if(!mesh_pick_exit(opt.mesh_name, m->table, exit_name, path)) {
            m->last_auto_exit = "-";
            return strategy{Strategy::proxy, "[[mesh: no exit]]\n"};
        }
        m->last_auto_exit = exit_name;
    }else{
        auto it = m->table.find(exit_name);
        if(it == m->table.end() || !it->second.fresh(now_ms())) {
            return strategy{Strategy::none, ""};
        }
        if(!(it->second.caps & MESH_CAP_EXIT)) {
            return strategy{Strategy::proxy, "[[mesh: no exit]]\n"};
        }
        if(!mesh_route(opt.mesh_name, m->table, exit_name, path)) {
            return strategy{Strategy::proxy, "[[mesh: no route]]\n"};
        }
    }
    //用活跃线路连首跳，挂逐跳凭据(identifier=最终目标)
    auto it = m->table.find(path.first_hop);
    if(it == m->table.end() || it->second.addrs.empty()) {
        //首跳来自活边，正常必有宣告地址；宣告替换可能瞬间清空
        return strategy{Strategy::proxy, "[[mesh: no route]]\n"};
    }
    if(!m->pick_conn(it->second, dest)) {
        return strategy{Strategy::proxy, "[[mesh: no route]]\n"};
    }
    dest->credit = m->mesh_credit;
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
    for(const auto& [name, e] : table) {
        char cost[32], updated[32];
        snprintf(cost, sizeof(cost), "%.1fms", e.cost);
        snprintf(updated, sizeof(updated), "%.1fs", (now - e.ts) / 1000.0);
        dp(param, "  %s %s caps:%s cost=%s probes=%u/%u updated=%s%s\n",
           name.c_str(), probe_state_str(e).c_str(), caps_str(e.caps).c_str(),
           e.cost > 0 ? cost : "-",
           e.ok, e.fail, e.ts ? updated : "-",
           e.seeded ? " seeded" : "");
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
    for(const auto& [name, e] : table) {
        if(e.cost > 0) {
            mine.emplace(name, e.cost);
        }
    }
    dump_edges(opt.mesh_name, mine);
    for(const auto& [name, e] : table) {
        if(!e.edges.empty()) {
            dump_edges(name, e.edges);
        }
    }
    dp(param, "routes:\n");
    for(const auto& [name, e] : table) {
        if(!e.fresh(now) || !(e.caps & MESH_CAP_EXIT)) {
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
    if(MeshManager* m = MeshManager::GetInstance()) {
        m->dump(dp, param);
    }
}
