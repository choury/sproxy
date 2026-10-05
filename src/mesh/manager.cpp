#include "mesh/manager.h"
#include "mesh/route.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "res/fetch.h"
#include "res/responser.h"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <sstream>

namespace {

constexpr int      MESH_FAIL_DEAD     = 3;       //连续探测失败轮数判死
constexpr uint32_t MESH_DEFAULT_MS    = 10'000;
constexpr uint32_t MESH_FIRST_DELAY_MS = 1'000;
constexpr size_t   MESH_SYNC_BODY_MAX = 1024 * 1024; //与 http_fetch 接收上限一致

MeshManager* instance = nullptr;

uint64_t now_ms() {
    return getutime() / 1000;
}

uint32_t env_interval(const char* name) {
    const char* s = getenv(name);
    if(!s || !*s) {
        return MESH_DEFAULT_MS;
    }
    char* end = nullptr;
    long v = strtol(s, &end, 10);
    if(end == s || *end != '\0' || v < 1 || v > 3600) {
        LOGE("[mesh] ignore bad %s=%s\n", name, s);
        return MESH_DEFAULT_MS;
    }
    return (uint32_t)v * 1000;
}

std::string join_str(const std::vector<std::string>& v, char sep) {
    std::string out;
    for(const auto& s : v) {
        if(!out.empty()) {
            out += sep;
        }
        out += s;
    }
    return out;
}

//宣告地址集：map 键天然有序，即排序规范化后的宣告
std::vector<std::string> addr_set(const MeshEntry& e) {
    std::vector<std::string> v;
    for(const auto& [addr, st] : e.addrs) {
        v.push_back(addr);
    }
    return v;
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
        if(parseDest(p->arg, &dest) || !dest.port) {
            LOGE("[mesh] bad mesh-peer: %s\n", p->arg);
            continue;
        }
        //dumpDest 会把 quic 的 scheme 序列化成 https，须按 protocol 还原，
        //否则 quic-only 节点的种子探测走了 TCP+TLS
        const char* scheme = strcmp(dest.protocol, "quic") == 0 ? "quic"
                           : strcmp(dest.protocol, "ssl") == 0 ? "https" : "http";
        char addr[DOMAINLIMIT + 32];
        snprintf(addr, sizeof(addr), "%s://%s:%u", scheme, dest.hostname, dest.port);
        MeshEntry& e = table[dest.hostname];
        e.seeded = true;
        //种子能力位未知，按可探测假设；收到宣告后覆盖
        e.caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        //ts 恒 0：种子是本机假设而非对端宣告，须输给任何通过时钟偏差检查的宣告
        e.addrs[addr]; //哨兵：已宣告未探测
    }
    probe_ms = env_interval("SPROXY_MESH_PROBE_INTERVAL");
    sync_ms = env_interval("SPROXY_MESH_SYNC_INTERVAL");
    //首轮 1s 快速收敛；job 不会自动重复，两个 round 末尾各自 UpdateJob 自续
    probe_job = AddJob([this]{ probe_round(); }, MESH_FIRST_DELAY_MS, 0);
    sync_job = AddJob([this]{ sync_round(); }, MESH_FIRST_DELAY_MS, 0);
}

const std::string& MeshManager::best_addr(const MeshEntry& e) const {
    const std::string* best_addr_p = nullptr;
    double best = 0;
    for(const auto& [addr, st] : e.addrs) {
        if(st.second < MESH_FAIL_DEAD && st.first > 0 && (best == 0 || st.first < best)) {
            best = st.first;
            best_addr_p = &addr;
        }
    }
    //无成功样本时退回首地址(排序规范化的宣告序)
    return best_addr_p ? *best_addr_p : e.addrs.begin()->first;
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
        if(e.probing || e.addrs.empty() || e.caps == 0) {
            continue;
        }
        e.probing = true;
        const std::string node = name;
        for(const auto& addr_st : e.addrs) {
            const std::string& addr = addr_st.first;
            Destination dest{};
            if(parseDest(addr.c_str(), &dest)) {
                //忽略坏 addrs
                e.probing = false;
                continue;
            }
            char buff[HEADLENLIMIT];
            int headlen = snprintf(buff, sizeof(buff), "GET localhost:%d/mesh/ping HTTP/1.1" CRLF CRLF, dest.port);
            auto req = UnpackHttpReq(buff, headlen);
            req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
            uint64_t t0 = getutime();
            uint32_t timeout = std::max(500u, std::min(5000u, probe_ms / 2));
            http_fetch(std::move(req), dest, "", [this, node, addr, t0](std::shared_ptr<HttpResHeader> res, std::string) {
                auto it = table.find(node);
                if(it == table.end()) {
                    return;
                }
                MeshEntry& e = it->second;
                e.probing = false;
                if(res && atoi(res->status) == 200) {
                    double rtt = (getutime() - t0) / 1000.0;
                    e.ok++;
                    e.addrs[addr] = {rtt, 0};
                    LOGD(DMESH, "probe %s ok %s %.1fms\n", node.c_str(), addr.c_str(), rtt);
                } else {
                    e.fail++;
                    auto& st = e.addrs[addr];
                    st.second++;
                    LOGD(DMESH, "probe %s fail %s (%s)\n", node.c_str(), addr.c_str(),
                         res ? res->status : "no response");
                }
                //活边 rtt = 各 addr 中未判死且成功过的最小值，无则 0
                double best = 0;
                for(const auto& [paddr, st] : e.addrs) {
                    if(st.second < MESH_FAIL_DEAD && st.first > 0 && (best == 0 || st.first < best)) {
                        best = st.first;
                    }
                }
                e.rtt = best;
            }, timeout);
        }
    }
    probe_job = UpdateJob(std::move(probe_job), [this]{ probe_round(); }, probe_ms);
}

void MeshManager::sync_round() {
    for(auto& [name, e] : table) {
        //纯入口节点(caps==0)不收任何入向连接；种子始终同步以便引导收敛
        if(e.syncing || e.caps == 0 || e.addrs.empty()) {
            continue;
        }
        //rtt = 0 代表没有ping成功过，先不进行同步
        if(!e.seeded && e.rtt == 0) {
            continue;
        }
        Destination dest{};
        if(parseDest(best_addr(e).c_str(), &dest)) {
            continue;
        }
        e.syncing = true;
        char buff[HEADLENLIMIT];
        int headlen = snprintf(buff, sizeof(buff), "POST localhost:%d/mesh/nodes HTTP/1.1" CRLF CRLF, dest.port);
        auto req = UnpackHttpReq(buff, headlen);
        req->set("Proxy-Authorization", encodeCredit(&mesh_credit));
        //回调远晚于本轮迭代执行，结构化绑定按 C++17 语义不能进闭包
        const std::string node = name;
        uint32_t timeout = std::max(2000u, std::min(10'000u, sync_ms));
        http_fetch(std::move(req), dest, serialize(), [this, node](std::shared_ptr<HttpResHeader> res, std::string body) {
            auto it = table.find(node);
            if(it == table.end()) {
                return;
            }
            it->second.syncing = false;
            if(!res || atoi(res->status) != 200) {
                LOGD(DMESH, "sync %s failed: %s\n", node.c_str(), res ? res->status : "no response");
                return;
            }
            merge(body);
        }, timeout);
    }
    sync_job = UpdateJob(std::move(sync_job), [this]{ sync_round(); }, sync_ms);
}

//每节点一行：N <名> <能力位> <ts> <addr|addr...|-> [对端=rtt ...]
//宣告与邻边同轮同 ts 携带，空边集显式表达(缺席轮内即为清空)
std::string MeshManager::serialize() const {
    std::ostringstream out;
    out << "N " << opt.mesh_name << " " << opt.mesh_caps << " " << now_ms() << " "
        << (self_addrs.empty() ? "-" : join_str(self_addrs, '|'));
    for(const auto& [name, e] : table) {
        if(e.rtt > 0) {
            out << " " << name << "=" << e.rtt;
        }
    }
    out << "\n";
    for(const auto& [name, e] : table) {
        out << "N " << name << " " << e.caps << " " << e.ts << " "
            << (e.addrs.empty() ? "-" : join_str(addr_set(e), '|'));
        for(const auto& [peer, rtt] : e.edges) {
            out << " " << peer << "=" << rtt;
        }
        out << "\n";
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
        if(name == opt.mesh_name) {
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
        std::vector<std::string> addrs;
        if(addrstr != "-") {
            std::istringstream as(addrstr);
            std::string addr;
            while(std::getline(as, addr, '|')) {
                if(!addr.empty()) {
                    addrs.emplace_back(addr);
                }
            }
        }
        //排序规范化：宣告按集合语义比较，存储序即 addrs 键序
        std::sort(addrs.begin(), addrs.end());
        std::map<std::string, double> edges;
        std::string pair;
        while(ls >> pair) {
            auto pos = pair.rfind('=');
            if(pos == std::string::npos) {
                continue;
            }
            double rtt = strtod(pair.c_str() + pos + 1, nullptr);
            if(rtt > 0) {
                edges[pair.substr(0, pos)] = rtt;
            }
        }
        auto it = table.find(name);
        if(it == table.end()) {
            MeshEntry e;
            e.caps = caps;
            e.ts = ts;
            for(const auto& a : addrs) {
                e.addrs[a]; //哨兵
            }
            e.edges = std::move(edges);
            table.emplace(name, std::move(e));
            LOGD(DMESH, "discovered %s addrs=[%s]\n", name.c_str(), join_str(addrs, ' ').c_str());
        } else if(addr_set(it->second) != addrs && !it->second.seeded) {
            LOGE("[mesh] %s changed addrs [%s] -> [%s], keep local\n", name.c_str(),
                 join_str(addr_set(it->second), ' ').c_str(), join_str(addrs, ' ').c_str());
        } else if(ts < it->second.ts) {
            //多径转发下旧轮次乱序到达，整行丢弃防回退
            continue;
        } else {
            //种子让位与常规刷新同路：旧地址探测状态随宣告集变化作废
            it->second.seeded = false;
            if(addr_set(it->second) != addrs) {
                it->second.addrs.clear();
                for(const auto& a : addrs) {
                    it->second.addrs[a];
                }
                it->second.rtt = 0;
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
    //按既定首跳落账：选首跳最优地址，挂逐跳凭据(identifier=最终目标)
    auto it = m->table.find(path.first_hop);
    if(it == m->table.end() || it->second.addrs.empty()) {
        //首跳来自活边，正常必有宣告地址；宣告替换可能瞬间清空
        return strategy{Strategy::proxy, "[[mesh: no route]]\n"};
    }
    if(parseDest(m->best_addr(it->second).c_str(), dest)) {
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
    if(strcmp(req->cr.user, "mesh") != 0 || !checksecret(&req->cr)) {
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
        dp(param, "  %s [%s] caps:%s rtt=%s probes=%u/%u updated=%s%s\n",
           name.c_str(), join_str(addr_set(e), ' ').c_str(), caps_str(e.caps).c_str(),
           e.rtt > 0 ? std::to_string(e.rtt).c_str() : "-",
           e.ok, e.fail, e.ts ? std::to_string((now - e.ts)/1000.0).c_str() : "-",
           e.seeded ? " seeded" : "");
    }
    dp(param, "auto exit: %s\n", last_auto_exit.empty() ? "-" : last_auto_exit.c_str());
    dp(param, "link states:\n");
    auto dump_edges = [&](const std::string& who, const std::map<std::string, double>& edges) {
        std::string es;
        for(const auto& [peer, rtt] : edges) {
            es += " " + peer + "@" + std::to_string(rtt).substr(0, 5) + "ms";
        }
        dp(param, "  %s:%s\n", who.c_str(), es.c_str());
    };
    std::map<std::string, double> mine;
    for(const auto& [name, e] : table) {
        if(e.rtt > 0) {
            mine.emplace(name, e.rtt);
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
