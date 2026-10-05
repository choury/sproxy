#include "manager.h"
#include "route.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/http/http_header.h"
#include "res/fetch.h"
#include "res/responser.h"

#include <json.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

MeshManager* MeshManager::instance = nullptr;

//由节点 URL 构造带 mesh 凭据的出站目的地；dest 已解析时只补凭据
static void inject_mesh_credit(Destination& dest) {
    strcpy(dest.credit.user, "mesh");
    snprintf(dest.credit.pass, sizeof(dest.credit.pass), "%s", opt.mesh_secret);
    dest.credit.identifier[0] = 0;
}

static bool make_mesh_dest(const std::string& url, Destination& dest) {
    if(parseDest(url.c_str(), &dest)) {
        return false;
    }
    inject_mesh_credit(dest);
    return true;
}

//条目 caps 字符串与能力位互转
static uint32_t caps_bits(const MeshEntry& e) {
    uint32_t bits = 0;
    if(e.has_cap("exit"))  bits |= MESH_CAP_EXIT;
    if(e.has_cap("relay")) bits |= MESH_CAP_RELAY;
    return bits;
}

static std::vector<std::string> caps_names(uint32_t bits) {
    std::vector<std::string> v;
    if(bits & MESH_CAP_EXIT)  v.push_back("exit");
    if(bits & MESH_CAP_RELAY) v.push_back("relay");
    return v;
}

//控制面请求，origin 形式：Dest 即消息自身的地址，设 localhost:拨号端口——localhost
//保证命中对端 local 规则，restrict-local 下还要求请求端口等于监听端口；实际连接的
//peer 由 http_fetch 的 dest 参数指定
static std::shared_ptr<HttpReqHeader> ctl_req(const Destination& dest,
                                              const char* method, const char* path) {
    char buff[HEADLENLIMIT];
    int headlen = snprintf(buff, sizeof(buff),
                           "%s %s HTTP/1.1" CRLF
                           "Authorization: %s" CRLF CRLF,
                           method, path, encodeCredit(&dest.credit).c_str());
    auto req = UnpackHttpReq(buff, headlen);
    strcpy(req->Dest.hostname, "localhost");
    req->Dest.port = dest.port;
    return req;
}

MeshManager* MeshManager::Instance() {
    return instance;
}

void MeshManager::Start() {
    assert(instance == nullptr);
    instance = new MeshManager();
    //测试专用加速旋钮（非配置项）：默认 10s/30s 的周期会让测试的收敛等待以分钟计。
    //0/负值会把周期 job 变成忙循环，直接报错退出
    if(const char* s = getenv("SPROXY_MESH_PROBE_INTERVAL")) {
        int v = atoi(s);
        if(v <= 0) {
            LOGE("mesh: bad SPROXY_MESH_PROBE_INTERVAL: %s\n", s);
            exit(1);
        }
        instance->probe_interval_ms = (uint32_t)v * 1000;
    }
    if(const char* s = getenv("SPROXY_MESH_GOSSIP_INTERVAL")) {
        int v = atoi(s);
        if(v <= 0) {
            LOGE("mesh: bad SPROXY_MESH_GOSSIP_INTERVAL: %s\n", s);
            exit(1);
        }
        instance->gossip_interval_ms = (uint32_t)v * 1000;
    }
    for(struct arg_list* p = opt.mesh_peers; p; p = p->next) {
        Destination dest{};
        if(parseDest(p->arg, &dest)) {
            LOGE("mesh: bad peer url, exit: %s\n", p->arg);
            exit(1);
        }
        // 节点名即 URL 主机名（addrs 主机名必须等于节点名）
        std::string name = dest.hostname;
        if(instance->nodes.count(name)) {
            LOGE("mesh: same host with multiple schemes, only the first is used: %s\n", p->arg);
            continue;
        }
        auto stra = getstrategy(dest.hostname, dest.port);
        if(stra.s == Strategy::proxy) {
            //peer 建连的 DNS 解析可能经代理链，命中 proxy 策略有递归进 mesh 的风险
            LOGE("mesh: peer %s hits proxy strategy, ignore\n", p->arg);
            continue;
        }
        inject_mesh_credit(dest);
        MeshNode node{};
        node.dest = dest;
        node.url = p->arg;
        node.is_static = true;
        instance->nodes.emplace(name, node);
    }
    instance->self_entry = instance->own_entry();
    instance->probePeers();
    instance->schedule_probe();
    instance->gossip_cycle();
    instance->schedule_gossip();
    LOG("mesh started: node=%s peers=%zu\n", opt.mesh_name, instance->nodes.size());
}

strategy MeshManager::Route(const std::string& target, Destination* dest) {
    *dest = Destination{};
    if(!instance) {
        return {Strategy::none, ""};
    }
    std::string exit_name = target;
    if(target == "auto") {
        exit_name = instance->pick_auto_exit();
        if(exit_name.empty()) {
            return {Strategy::proxy, "[[mesh: no exit]]\n"};
        }
    }
    if(exit_name == opt.mesh_name) {
        return {Strategy::direct, ""};
    }
    if(instance->nodes.count(exit_name) == 0) {
        return {Strategy::none, ""};
    }
    //逐跳路由：下一跳可能是出口自身（直连）或中继节点；
    //下一跳由最短路选出，天然满足 dist(下一跳→出口) < dist(本节点→出口) 的防环递减
    std::string nexthop = instance->route_to(exit_name);
    auto hop_it = instance->nodes.find(nexthop);
    if(hop_it == instance->nodes.end()) {
        return {Strategy::proxy, "[[mesh: no route]]\n"};
    }
    *dest = hop_it->second.dest;
    snprintf(dest->credit.identifier, sizeof(dest->credit.identifier), "%s", exit_name.c_str());
    return {Strategy::proxy, ""};
}

void MeshManager::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
}

const MeshEntry& MeshManager::own_entry() {
    //addrs 由节点名 + 本节点监听端口构造（主机名必须等于节点名）；
    //无监听的纯入口节点 addrs 为空
    if(self_entry.seen + (int64_t)gossip_interval_ms / 1000 > time(NULL)) {
        return self_entry;
    }
    self_entry = MeshEntry{};
    self_entry.name = opt.mesh_name;
    for(struct bind_list* n = opt.listen_list; n; n = n->next) {
        const struct BindInfo& info = n->info;
        if(info.port == 0 || info.sni_mode) {
            continue;
        }
        const char* scheme = nullptr;
        if(strcmp(info.protocol, "ssl") == 0) {
            scheme = "https";
        } else if(strcmp(info.protocol, "quic") == 0) {
            scheme = "quic";
        } else if(strcmp(info.protocol, "http") == 0) {
            scheme = "http";
        }
        if(scheme) {
            self_entry.addrs.push_back(std::string(scheme) + "://" + opt.mesh_name
                                       + ":" + std::to_string(info.port));
        }
    }
    self_entry.caps = caps_names(opt.mesh_caps);
    self_entry.seen = time(NULL);
    MeshGossip::sign_entry(self_entry, opt.mesh_secret);
    return self_entry;
}

std::string MeshManager::own_entry_json() {
    return MeshGossip::entry_to_json(own_entry());
}

std::string MeshManager::export_entries_json() {
    GossipPayload payload;
    payload.entries.push_back(own_entry());
    int64_t now = time(NULL);
    for(auto& [name, node] : nodes) {
        if(node.entry.seen != 0) {
            //已有该节点自宣的条目（含静态互联的），原样转发其签名条目；
            //不新鲜的不再扩散（peer 可能已死）；窗口与 learn 侧一致
            if(MeshGossip::fresh_entry(node.entry, now,
                                       std::max<int64_t>(300, (int64_t)gossip_interval_ms / 1000))) {
                payload.entries.push_back(node.entry);
            }
            continue;
        }
        if(!node.is_static) {
            continue;
        }
        //从未收到自宣：按本地认知构造（成员级签名），否则纯静态互联无法被发现
        MeshEntry e;
        e.name = name;
        e.addrs = {node.url};
        e.caps = caps_names(node.caps);
        e.seen = now;
        MeshGossip::sign_entry(e, opt.mesh_secret);
        payload.entries.push_back(e);
    }
    //链路状态随载荷传递性泛洪：分区拓扑下两跳以外的边否则永远进不了入口的图
    payload.metrics.push_back(own_metrics());
    int64_t ttl = (int64_t)gossip_interval_ms / 1000 * 20;
    for(auto& [reporter, links] : link_states) {
        auto ts = link_ts.find(reporter);
        if(ts != link_ts.end() && now - ts->second <= ttl) {
            LinkReport r;
            r.name = reporter;
            r.ts = ts->second;
            r.links = links;
            payload.metrics.push_back(std::move(r));
        }
    }
    return MeshGossip::build_payload(payload);
}

std::pair<size_t, size_t> MeshManager::learn_entries(std::vector<MeshEntry> es) {
    size_t accepted = 0;
    size_t valid = 0;
    for(auto& e : es) {
        //未通过结构校验的 name 可能含换行等，不进日志
        if(!MeshGossip::valid_entry(e)) {
            LOGE("(%s) mesh: drop malformed entry\n", opt.mesh_name);
            continue;
        }
        if(!MeshGossip::fresh_entry(e, time(NULL),
                                    std::max<int64_t>(300, (int64_t)gossip_interval_ms / 1000))
           || !MeshGossip::verify_entry(e, opt.mesh_secret)) {
            LOGE("(%s) mesh: drop invalid entry: %s\n", opt.mesh_name, e.name.c_str());
            continue;
        }
        valid++;
        if(e.name == opt.mesh_name) {
            continue;
        }
        auto it = nodes.find(e.name);
        if(it != nodes.end()) {
            //同名异址优先于 seen 单调检查告警：命名冲突的判定不应被同秒时间戳吞掉。
            //按设计放弃后到者；真实迁移靠旧条目 TTL 过期后自然收敛
            if(it->second.entry.seen != 0 && it->second.entry.addrs != e.addrs) {
                LOGE("(%s) mesh: entry %s changed addrs while fresh, keep stored\n",
                     opt.mesh_name, e.name.c_str());
                continue;
            }
            if(e.seen <= it->second.entry.seen) {
                continue; //合法但非更新
            }
            it->second.entry = e;
            it->second.caps = caps_bits(e);
            accepted++;
            continue;
        }
        //发现新节点：解析地址并纳入探测
        if(e.addrs.empty()) {
            continue;
        }
        Destination dest{};
        if(!make_mesh_dest(e.addrs[0], dest)) {
            LOGE("(%s) mesh: bad addr in entry %s\n", opt.mesh_name, e.name.c_str());
            continue;
        }
        MeshNode node{};
        node.dest = dest;
        node.url = e.addrs[0];
        node.entry = e;
        node.is_static = false;
        node.caps = caps_bits(e);
        nodes.emplace(e.name, node);
        accepted++;
        LOG("(%s) mesh: discovered node %s (%s)\n",
            opt.mesh_name, e.name.c_str(), e.addrs[0].c_str());
    }
    return {accepted, valid};
}

void MeshManager::schedule_probe() {
    probe_job = UpdateJob(std::move(probe_job), [this]{
        probePeers();
        schedule_probe();
    }, probe_interval_ms);
}

void MeshManager::probePeers() {
    for(auto& [name, node] : nodes) {
        if(node.caps == 0) {
            continue; //入口节点：不探测，避免周期性入向连接
        }
        if(probe_inflight.count(name)) {
            continue; //上一次探测未返回
        }
        probe(name, node);
    }
}

void MeshManager::probe(const std::string& name, MeshNode& node) {
    uint64_t send_us = getutime();
    probe_inflight.insert(name);
    http_fetch(ctl_req(node.dest, "GET", "/mesh/ping"), node.dest, "",
               [this, name, send_us](std::shared_ptr<HttpResHeader> res, std::string) {
        probe_inflight.erase(name);
        auto it = nodes.find(name);
        if(it == nodes.end()) {
            return; //探测期间节点已过期移除
        }
        if(!res || atoi(res->status) != 200) {
            it->second.probe_fail++;
            if(res) {
                LOGE("(%s) mesh probe %s got %s\n", opt.mesh_name, name.c_str(), res->status);
            }
            return;
        }
        double rtt = (getutime() - send_us) / 1000.0;
        auto& node = it->second;
        node.rtt_ms = node.rtt_ms > 0 ? node.rtt_ms * 0.875 + rtt * 0.125 : rtt;
        node.last_ok_ms = getmtime();
        node.probe_ok++;
        LOGD(DMESH, "mesh probe %s: rtt=%.1fms\n", name.c_str(), rtt);
    }, probe_interval_ms * 5 + 1000);
}

void MeshManager::schedule_gossip() {
    gossip_job = UpdateJob(std::move(gossip_job), [this]{
        gossip_cycle();
        schedule_gossip();
    }, gossip_interval_ms);
}

void MeshManager::gossip_cycle() {
    expire_learned();
    if(nodes.empty()) {
        return;
    }
    //心跳轮转：每周期向 ⌈P/8⌉ 个 peer 发 pull+push，保证 ≤8 个周期覆盖全部 peer
    //（peer 连接的 300s 空闲计时由探测请求重臂，h2 PING 不重臂 idle）
    std::vector<std::string> names;
    for(auto& [name, node] : nodes) {
        if(node.caps == 0) {
            continue; //入口节点：控制面零入向连接（探测与 gossip 都不发起）
        }
        bool probed = node.last_ok_ms != 0 || node.probe_fail > 0;
        if(probed && !alive(node)) {
            continue; //探测过且失联的节点不占轮转名额；从未探测的（启动期/新发现）放行，
                      //否则首个 gossip 周期整轮空转、初次交换推迟一个周期
        }
        names.push_back(name);
    }
    if(names.empty()) {
        return;
    }
    size_t batch = (names.size() + 7) / 8;
    std::string own = own_entry_json();
    for(size_t i = 0; i < batch; i++) {
        const std::string& name = names[(gossip_offset + i) % names.size()];
        auto it = nodes.find(name);
        if(it == nodes.end()) {
            continue; //周期内被过期移除
        }
        http_fetch(ctl_req(it->second.dest, "GET", "/mesh/nodes"), it->second.dest, "",
                   [this](std::shared_ptr<HttpResHeader> res, std::string body) {
            if(res && atoi(res->status) == 200) {
                auto payload = MeshGossip::parse_payload(body);
                learn_entries(std::move(payload.entries));
                learn_metrics(std::move(payload.metrics));
            }
        }, probe_interval_ms * 5 + 1000);
        http_fetch(ctl_req(it->second.dest, "POST", "/mesh/announce"), it->second.dest, own,
                   [name](std::shared_ptr<HttpResHeader> res, std::string) {
            LOGD(DMESH, "mesh announce to %s: %s\n", name.c_str(), res ? res->status : "NULL");
        }, probe_interval_ms * 5 + 1000);
    }
    gossip_offset = (gossip_offset + batch) % names.size();
}

//自身链路 = 近期探测成功过的邻居（与判活同口径），有向：仅本节点→对端
LinkReport MeshManager::own_metrics() {
    LinkReport r;
    r.name = opt.mesh_name;
    r.ts = time(NULL);
    for(auto& [name, node] : nodes) {
        if(node.rtt_ms > 0 && alive(node)) {
            r.links[name] = node.rtt_ms;
        }
    }
    return r;
}

std::string MeshManager::own_metrics_json() {
    return MeshGossip::link_report_json(own_metrics());
}

void MeshManager::learn_metrics(std::vector<LinkReport> reports) {
    int64_t now = time(NULL);
    //边 TTL（20× gossip 周期，默认 600s）：从上报时间起算，
    //泛洪逐跳携带原始 ts，死节点停止续报后其边全网过期
    int64_t ttl = (int64_t)gossip_interval_ms / 1000 * 20;
    for(auto& r : reports) {
        if(r.name == opt.mesh_name || !nodes.count(r.name)) {
            continue; //只采信已知节点的上报
        }
        if(r.ts <= 0 || now - r.ts > ttl || r.ts - now > 300) {
            continue; //过期或时钟超前的上报不采信
        }
        //只接受比已存更新鲜的同源上报
        auto ts_it = link_ts.find(r.name);
        if(ts_it != link_ts.end() && r.ts < ts_it->second) {
            continue;
        }
        link_states[r.name] = std::move(r.links);
        link_ts[r.name] = r.ts;
    }
}

//近期（5 个探测周期内）探测成功过；失联节点的残留 rtt 不可信
bool MeshManager::alive(const MeshNode& node) const {
    return node.last_ok_ms != 0
           && getmtime() - node.last_ok_ms < (uint64_t)probe_interval_ms * 5;
}

std::string MeshManager::route_to(const std::string& exit_name, double* cost_out) {
    //组图：自身探测（与判活同口径，残留 rtt 不算边）+ 新鲜的链路状态上报。
    //图为有向：A→B 的边只来自 A 的上报，死节点的陈旧自宣无法虚构出指向它的边
    std::map<std::string, std::map<std::string, double>> links;
    int64_t now = time(NULL);
    int64_t ttl = (int64_t)gossip_interval_ms / 1000 * 20;
    for(auto it = link_states.begin(); it != link_states.end();) {
        auto ts = link_ts.find(it->first);
        if(ts == link_ts.end() || now - ts->second > ttl || !nodes.count(it->first)) {
            if(ts != link_ts.end()) {
                link_ts.erase(ts);
            }
            it = link_states.erase(it);
            continue;
        }
        links[it->first] = it->second;
        it++;
    }
    LinkReport mine = own_metrics();
    links[opt.mesh_name] = std::move(mine.links);
    //中间跳须宣告 relay 能力；出口自身显式加入集合（显式指定任意表内节点为出口不受限）
    std::set<std::string> routable;
    for(auto& [name, node] : nodes) {
        if(node.caps & MESH_CAP_RELAY) {
            routable.insert(name);
        }
    }
    routable.insert(exit_name);
    auto [nexthop, cost] = MeshRoute::shortest_path(links, opt.mesh_name, exit_name, routable);
    //路由滞回（代价棘轮）：旧下一跳在当前图中仍可达出口、且新路径对旧路径的
    //实时代价改善不足 20% 时保持原选择；否则切换。
    //旧路径代价按当前图实时计算（含本节点→旧下一跳的边），历史缓存值不参与比较
    auto cached = route_cache.find(exit_name);
    if(cached != route_cache.end() && !cached->second.nexthop.empty()
       && nexthop != cached->second.nexthop && !nexthop.empty()
       && routable.count(cached->second.nexthop)) {
        double via_old = 0;
        auto& my_edges = links[opt.mesh_name];
        auto edge = my_edges.find(cached->second.nexthop);
        if(edge != my_edges.end()) {
            auto [old_nh, old_dist] = MeshRoute::shortest_path(links, cached->second.nexthop, exit_name, routable);
            if(!old_nh.empty()) {
                via_old = edge->second + old_dist;
            }
        }
        if(via_old > 0 && cost > via_old * 0.8) {
            route_cache[exit_name] = RouteChoice{cached->second.nexthop, via_old};
            if(cost_out) {
                *cost_out = via_old;
            }
            return cached->second.nexthop;
        }
    }
    route_cache[exit_name] = RouteChoice{nexthop, cost};
    if(cost_out) {
        *cost_out = cost;
    }
    return nexthop;
}

void MeshManager::expire_learned() {
    int64_t now = time(NULL);
    int64_t ttl = gossip_interval_ms / 1000 * 10;
    for(auto it = nodes.begin(); it != nodes.end();) {
        if(it->second.is_static || it->second.entry.seen + ttl >= now) {
            it++;
            continue;
        }
        LOG("(%s) mesh: node %s expired\n", opt.mesh_name, it->first.c_str());
        route_cache.erase(it->first);
        it = nodes.erase(it);
    }
}

std::string MeshManager::pick_auto_exit() {
    uint64_t now = getmtime();
    //候选 = 有出口能力且当前有路可达的节点（路径可经中继），代价取最短路
    std::string best;
    double best_rtt = 0;
    for(auto& [name, node] : nodes) {
        if(!(node.caps & MESH_CAP_EXIT)) {
            continue;
        }
        double cost = 0;
        if(route_to(name, &cost).empty()) {
            continue;
        }
        if(best.empty() || cost < best_rtt) {
            best = name;
            best_rtt = cost;
        }
    }
    if(best.empty()) {
        auto_exit.clear();
        return "";
    }
    double cur_cost = 0;
    bool cur_alive = !auto_exit.empty() && !route_to(auto_exit, &cur_cost).empty();
    //切换滞回：现任失联立即切；否则需新路径比现任当前路由代价改善超过 20%
    //且距上次切换 >30s（用路由代价而非直连 rtt，避免陈旧直连样本卡死切换）
    if(auto_exit.empty() || !cur_alive
       || (best != auto_exit && best_rtt < cur_cost * 0.8
           && now - auto_switch_ms > 30000)) {
        if(auto_exit.empty()) {
            LOG("(%s) mesh: auto exit picked %s (%.1fms)\n",
                opt.mesh_name, best.c_str(), best_rtt);
        } else if(best != auto_exit) {
            LOG("(%s) mesh: auto exit switch %s -> %s (%.1fms)\n",
                opt.mesh_name, auto_exit.c_str(), best.c_str(), best_rtt);
        }
        auto_exit = best;
        auto_rtt = best_rtt;
        auto_switch_ms = now;
    }
    return auto_exit;
}

void dump_mesh(Dumper dp, void* param) {
    if(!MeshManager::instance) {
        return;
    }
    MeshManager& m = *MeshManager::instance;
    dp(param, "======================================\n");
    dp(param, "mesh node: %s, peers: %zu\n", opt.mesh_name, m.nodes.size());
    uint64_t now = getmtime();
    for(auto& [name, node] : m.nodes) {
        char last_ok[40] = "-";
        if(node.last_ok_ms) {
            snprintf(last_ok, sizeof(last_ok), "%" PRIu64 "ms ago", now - node.last_ok_ms);
        }
        dp(param, "  %s [%s]: rtt=%.1fms probes=%" PRIu64 "/%" PRIu64 " last_ok=%s%s%s%s\n",
           name.c_str(), node.url.c_str(), node.rtt_ms,
           node.probe_ok, node.probe_fail, last_ok,
           node.is_static ? " static" : "",
           node.caps & MESH_CAP_EXIT ? " exit" : "",
           node.caps & MESH_CAP_RELAY ? " relay" : "");
    }
    if(!m.auto_exit.empty()) {
        dp(param, "  auto exit: %s (%.1fms)\n", m.auto_exit.c_str(), m.auto_rtt);
    }
    for(auto& [reporter, peers] : m.link_states) {
        auto ts = m.link_ts.find(reporter);
        if(ts == m.link_ts.end()) {
            continue;
        }
        dp(param, "  links from %s (age=%llds):\n", reporter.c_str(),
           (long long)(time(NULL) - ts->second));
        for(auto& [peer, rtt] : peers) {
            dp(param, "    %s: %.2fms\n", peer.c_str(), rtt);
        }
    }
    for(auto& [exit_name, choice] : m.route_cache) {
        if(!choice.nexthop.empty()) {
            dp(param, "  route %s via %s (%.1fms)\n",
               exit_name.c_str(), choice.nexthop.c_str(), choice.cost);
        }
    }
    dp(param, "======================================\n");
}
