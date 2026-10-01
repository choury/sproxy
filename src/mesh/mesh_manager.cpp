#include "mesh_manager.h"
#include "mesh_route.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"
#include "res/responser.h"
#include "res/host.h"

#include <json.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>

MeshManager* MeshManager::instance = nullptr;

// 剥除请求上所有 X-Mesh-* 头：入口注入前清除客户端伪造的头，
// 出口/凭据无效时防止 mesh 内部头透传到目标站
static void stripMeshHeaders(std::shared_ptr<HttpReqHeader> req) {
    std::vector<std::string> to_del;
    for(auto& [name, value] : req->getall()) {
        if(strncasecmp(name.c_str(), "x-mesh-", 7) == 0) {
            to_del.push_back(name);
        }
    }
    for(auto& name : to_del) {
        req->del(name);
    }
}

static bool hasMeshHeaders(std::shared_ptr<HttpReqHeader> req) {
    for(auto& [name, value] : req->getall()) {
        if(strncasecmp(name.c_str(), "x-mesh-", 7) == 0) {
            return true;
        }
    }
    return false;
}

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

bool MeshManager::Started() {
    return instance != nullptr;
}

MeshManager* MeshManager::Instance() {
    return instance;
}

bool MeshManager::IsSelfExit(const char* name) {
    return instance && strcmp(name, opt.mesh_name) == 0;
}

bool MeshManager::CheckMeshCredit(const char* auth, bool need_identifier, struct Credit* cr) {
    return auth && decodeauth(auth, cr)
           && strcmp(cr->user, "mesh") == 0
           && (!need_identifier || cr->identifier[0])
           && checksecret(auth, cr);
}

void MeshManager::Start() {
    if(instance || !opt.mesh_name) {
        return;
    }
    instance = new MeshManager();
    for(struct arg_list* p = opt.mesh_peers; p; p = p->next) {
        Destination dest{};
        if(parseDest(p->arg, &dest)) {
            LOGE("mesh: bad peer url, exit: %s\n", p->arg);
            exit(1);
        }
        // 节点名即 URL 主机名（docs/mesh.md 2.1：addrs 主机名必须等于节点名）
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
    instance->probe_interval_ms = opt.mesh_probe_interval * 1000;
    instance->gossip_interval_ms = opt.mesh_gossip_interval * 1000;
    instance->self_entry = instance->own_entry();
    instance->probePeers();
    instance->schedule_probe();
    instance->gossip_cycle();
    instance->schedule_gossip();
    LOG("mesh started: node=%s peers=%zu\n", opt.mesh_name, instance->nodes.size());
}

void MeshManager::Dispatch(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                           const std::string& ext) {
    if(!instance) {
        return response(rw, HttpResHeader::create(S502, sizeof(S502), req->request_id),
                        "[[mesh not enabled]]\n");
    }
    instance->dispatch(req, rw, ext);
}

bool MeshManager::Forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    if(!instance) {
        stripMeshHeaders(req);
        return true;
    }
    return instance->forward(req, rw);
}

bool MeshManager::HasMeshHeaders(std::shared_ptr<HttpReqHeader> req) {
    return hasMeshHeaders(req);
}

void MeshManager::dispatch(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                           const std::string& ext) {
    uint64_t id = req->request_id;
    stripMeshHeaders(req);
    std::string name = ext.substr(strlen(MESH_SCHEME));
    if(req->mesh_exited) {
        // 出口侧本机策略把目标再次送进 mesh：配置级环路，拒绝
        return response(rw, HttpResHeader::create(S508, sizeof(S508), id),
                        "[[mesh: loop detected]]\n");
    }
    if(name == "auto") {
        name = pick_auto_exit();
        if(name.empty()) {
            return response(rw, HttpResHeader::create(S502, sizeof(S502), id),
                            "[[mesh: no exit]]\n");
        }
    }
    auto node_it = nodes.find(name);
    if(node_it == nodes.end()) {
        return response(rw, HttpResHeader::create(S502, sizeof(S502), id),
                        "[[mesh: unknown node]]\n");
    }
    //逐跳路由：下一跳可能是出口自身（直连）或中继节点
    std::string nexthop = route_to(name);
    auto hop_it = nodes.find(nexthop);
    if(hop_it == nodes.end()) {
        return response(rw, HttpResHeader::create(S502, sizeof(S502), id),
                        "[[mesh: no route]]\n");
    }
    Destination dest = hop_it->second.dest;
    snprintf(dest.credit.identifier, sizeof(dest.credit.identifier), "%s", name.c_str());
    req->chain_proxy = true;
    req->set("Proxy-Authorization", encodeCredit(&dest.credit));
    req->set("X-Mesh-Exit", name);
    req->set("X-Mesh-Hops", opt.mesh_maxhops);
    LOGD(DMESH, "mesh dispatch: %s exit=%s via=%s\n",
         req->geturl().c_str(), name.c_str(),
         nexthop == name ? "direct" : nexthop.c_str());
    Host::distribute(req, dest, rw);
}

bool MeshManager::forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    const char* auth = req->get("Proxy-Authorization");
    struct Credit cr{};
    // identifier（最终出口名）承载在凭据里，与头分离的伪造不进入 mesh 语义
    if(!CheckMeshCredit(auth, true, &cr)) {
        stripMeshHeaders(req);
        return true;
    }
    if(strcmp(cr.identifier, opt.mesh_name) == 0) {
        // 本节点是出口：剥除 mesh 标记后继续正常流程。
        // Proxy-Authorization 必须先删，否则 getBackend 会把 identifier 当 rproxy 后端名
        stripMeshHeaders(req);
        req->del("Proxy-Authorization");
        req->mesh_exited = true;
        LOGD(DMESH, "mesh exit: %s\n", req->geturl().c_str());
        return true;
    }
    //中继路径：本节点不是出口，按路由把请求送往下一跳
    if(opt.mesh_relay != 0) { //off
        response(rw, HttpResHeader::create(S403, sizeof(S403), req->request_id),
                 "[[mesh: relay disabled]]\n");
        return false;
    }
    //缺失/非数字的 hops 视为 0
    const char* hops_str = req->get("X-Mesh-Hops");
    int hops = hops_str ? atoi(hops_str) : 0;
    if(hops <= 0) {
        response(rw, HttpResHeader::create(S508, sizeof(S508), req->request_id),
                 "[[mesh: hop limit exceeded]]\n");
        return false;
    }
    std::string nexthop = route_to(cr.identifier);
    auto hop_it = nodes.find(nexthop);
    if(hop_it == nodes.end()) {
        response(rw, HttpResHeader::create(S502, sizeof(S502), req->request_id),
                 "[[mesh: no route]]\n");
        return false;
    }
    //下一跳由最短路选出，天然满足 dist(下一跳→出口) < dist(本节点→出口) 的防环递减
    Destination dest = hop_it->second.dest;
    snprintf(dest.credit.identifier, sizeof(dest.credit.identifier), "%s", cr.identifier);
    req->chain_proxy = true;
    req->set("Proxy-Authorization", encodeCredit(&dest.credit));
    req->set("X-Mesh-Hops", (uint64_t)(hops - 1));
    appendVia(req);
    LOGD(DMESH, "mesh relay: %s exit=%s via=%s hops=%d\n",
         req->geturl().c_str(), cr.identifier, nexthop.c_str(), hops - 1);
    Host::distribute(req, dest, rw);
    return false;
}

const MeshEntry& MeshManager::own_entry() {
    //addrs 由节点名 + 本节点监听端口构造（主机名必须等于节点名）；
    //无监听的纯入口节点 addrs 为空
    if(self_entry.seen + (int64_t)opt.mesh_gossip_interval > time(NULL)) {
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
    if(opt.mesh_exit == 0) {
        self_entry.caps = {"exit"};
    }
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
                                       std::max<int64_t>(300, (int64_t)opt.mesh_gossip_interval))) {
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
        if(node.exit_cap) {
            e.caps = {"exit"};
        }
        e.seen = now;
        MeshGossip::sign_entry(e, opt.mesh_secret);
        payload.entries.push_back(e);
    }
    //链路状态随载荷传递性泛洪：分区拓扑下两跳以外的边否则永远进不了入口的图
    payload.metrics.push_back(own_metrics());
    int64_t ttl = (int64_t)opt.mesh_gossip_interval * 20;
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
                                    std::max<int64_t>(300, (int64_t)opt.mesh_gossip_interval))
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
            it->second.exit_cap = e.has_cap("exit");
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
        node.exit_cap = e.has_cap("exit");
        nodes.emplace(e.name, node);
        accepted++;
        LOG("(%s) mesh: discovered node %s (%s)\n",
            opt.mesh_name, e.name.c_str(), e.addrs[0].c_str());
    }
    return {accepted, valid};
}

//发一次控制面请求：构造经 peer 连接的 HTTP 请求直连对端（绕过本机 distribute，
//否则 localhost 目标会被本机 local 策略短路）
void MeshManager::request(const Destination& dest,
                          const char* method, const char* path, const std::string& body,
                          std::function<void(int, std::string)> done) {
    char buff[HEADLENLIMIT];
    int headlen;
    if(body.empty()) {
        headlen = snprintf(buff, sizeof(buff),
                           "%s %s HTTP/1.1" CRLF
                           "Host: localhost" CRLF
                           "Proxy-Authorization: %s" CRLF CRLF,
                           method, path, encodeCredit(&dest.credit).c_str());
    } else {
        headlen = snprintf(buff, sizeof(buff),
                           "%s %s HTTP/1.1" CRLF
                           "Host: localhost" CRLF
                           "Proxy-Authorization: %s" CRLF
                           "Content-Length: %zu" CRLF CRLF,
                           method, path, encodeCredit(&dest.credit).c_str(), body.size());
    }
    auto req = UnpackHttpReq(buff, headlen);
    struct State {
        std::function<void(int, std::string)> done;
        std::string body;
        int status = -1;
        bool fired = false;
    };
    auto state = std::make_shared<State>();
    state->done = std::move(done);
    uint64_t seq = ++ctl_seq;
    //请求结束后必须向 Responser 发 CHANNEL_ABORT 回收流表项（同 Guest::deqReq 模式）。
    //MemRWer 可能仍在自身的事件调用栈内触发回调，释放必须延迟一拍（同 Proxy2::Clean 模式）
    auto finish = [this, seq, state]{
        if(!state->fired) {
            state->fired = true;
            state->done(state->status, std::move(state->body));
        }
        addjob_with_name([this, seq]{
            auto it = ctl_inflight.find(seq);
            if(it == ctl_inflight.end()) {
                return;
            }
            auto flight = std::move(it->second);
            ctl_inflight.erase(it);
            flight.rw->push_signal(Signal::CHANNEL_ABORT);
        }, "mesh ctl finish", 0, JOB_FLAGS_AUTORELEASE);
    };
    auto cb = IMemRWerCallback::create();
    cb->onHeader([state](std::shared_ptr<HttpResHeader> res) {
        state->status = atoi(res->status);
    })->onData([finish, state](Buffer&& bb) {
        if(bb.len == 0) {
            finish();
            return 0;
        }
        //节点表响应上限 1MB（约 10^2 个条目），超限按畸形响应丢弃并掐断连接
        if(state->body.size() + bb.len > 1024 * 1024) {
            state->body.clear();
            finish();
            return (int)bb.len;
        }
        state->body.append((const char*)bb.data(), bb.len);
        return (int)bb.len;
    })->onSignal([finish](Signal) {
        finish(); //status 仍为 -1 或为 Host 的 503 错误应答
    })->onCap([]{
        return (size_t)BUF_LEN;
    })->onWrite([](uint64_t){});

    Destination local{};
    strcpy(local.hostname, "localhost");
    auto rw = std::make_shared<MemRWer>(local, req->Dest, cb);
    ctl_inflight.emplace(seq, Inflight{rw, cb});
    //h1 peer 无传输层保活，连接存活但不应答时靠本超时兜底回收
    addjob_with_name([finish]{finish();}, "mesh ctl timeout",
                     probe_interval_ms * 5 + 1000, JOB_FLAGS_AUTORELEASE);
    if(!body.empty()) {
        rw->push_data({body.data(), body.size()});
    }
    rw->push_data({nullptr});
    Host::distribute(req, dest, rw);
}

void MeshManager::schedule_probe() {
    probe_job = UpdateJob(std::move(probe_job), [this]{
        probePeers();
        schedule_probe();
    }, probe_interval_ms);
}

void MeshManager::probePeers() {
    for(auto& [name, node] : nodes) {
        if(probe_inflight.count(name)) {
            continue; //上一次探测未返回
        }
        probe(name, node);
    }
}

void MeshManager::probe(const std::string& name, MeshNode& node) {
    uint64_t send_us = getutime();
    probe_inflight.insert(name);
    request(node.dest, "GET", "/mesh/ping", "",
            [this, name, send_us](int status, std::string) {
        probe_inflight.erase(name);
        auto it = nodes.find(name);
        if(it == nodes.end()) {
            return; //探测期间节点已过期移除
        }
        if(status != 200) {
            it->second.probe_fail++;
            if(status > 0) {
                LOGE("(%s) mesh probe %s got %d\n", opt.mesh_name, name.c_str(), status);
            }
            return;
        }
        double rtt = (getutime() - send_us) / 1000.0;
        auto& node = it->second;
        node.rtt_ms = node.rtt_ms > 0 ? node.rtt_ms * 0.875 + rtt * 0.125 : rtt;
        node.last_ok_ms = getmtime();
        node.probe_ok++;
        LOGD(DMESH, "mesh probe %s: rtt=%.1fms\n", name.c_str(), rtt);
    });
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
        if(node.entry.addrs.empty() && !node.is_static) {
            continue; //纯入口节点（无地址）不可拉取
        }
        if(!alive(node)) {
            continue; //失联节点不占轮转名额，避免稀释活跃 peer 的 touch 上界
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
        request(it->second.dest, "GET", "/mesh/nodes", "",
                [this](int status, std::string body) {
            if(status == 200) {
                auto payload = MeshGossip::parse_payload(body);
                learn_entries(std::move(payload.entries));
                learn_metrics(std::move(payload.metrics));
            }
        });
        request(it->second.dest, "POST", "/mesh/announce", own,
                [name](int status, std::string) {
            LOGD(DMESH, "mesh announce to %s: %d\n", name.c_str(), status);
        });
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
    //边 TTL（20× gossip 周期，默认 600s，docs/mesh.md 6.1）：从上报时间起算，
    //泛洪逐跳携带原始 ts，死节点停止续报后其边全网过期
    int64_t ttl = (int64_t)opt.mesh_gossip_interval * 20;
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
    int64_t ttl = (int64_t)opt.mesh_gossip_interval * 20;
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
    std::set<std::string> routable;
    for(auto& [name, node] : nodes) {
        routable.insert(name);
    }
    auto [nexthop, cost] = MeshRoute::shortest_path(
        links, opt.mesh_name, exit_name, routable, opt.mesh_maxhops);
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
            auto [old_nh, old_dist] = MeshRoute::shortest_path(
                links, cached->second.nexthop, exit_name, routable, opt.mesh_maxhops);
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
    int64_t ttl = opt.mesh_gossip_interval * 10;
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
        if(!node.exit_cap) {
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

void MeshManager::dump_stat(Dumper dp, void* param) {
    dp(param, "======================================\n");
    dp(param, "mesh node: %s, peers: %zu\n", opt.mesh_name, nodes.size());
    uint64_t now = getmtime();
    for(auto& [name, node] : nodes) {
        char last_ok[40] = "-";
        if(node.last_ok_ms) {
            snprintf(last_ok, sizeof(last_ok), "%" PRIu64 "ms ago", now - node.last_ok_ms);
        }
        dp(param, "  %s [%s]: rtt=%.1fms probes=%" PRIu64 "/%" PRIu64 " last_ok=%s%s%s\n",
           name.c_str(), node.url.c_str(), node.rtt_ms,
           node.probe_ok, node.probe_fail, last_ok,
           node.is_static ? " static" : "",
           node.exit_cap ? " exit" : "");
    }
    if(!auto_exit.empty()) {
        dp(param, "  auto exit: %s (%.1fms)\n", auto_exit.c_str(), auto_rtt);
    }
    for(auto& [reporter, peers] : link_states) {
        auto ts = link_ts.find(reporter);
        if(ts == link_ts.end()) {
            continue;
        }
        dp(param, "  links from %s (age=%llds):\n", reporter.c_str(),
           (long long)(time(NULL) - ts->second));
        for(auto& [peer, rtt] : peers) {
            dp(param, "    %s: %.2fms\n", peer.c_str(), rtt);
        }
    }
    for(auto& [exit_name, choice] : route_cache) {
        if(!choice.nexthop.empty()) {
            dp(param, "  route %s via %s (%.1fms)\n",
               exit_name.c_str(), choice.nexthop.c_str(), choice.cost);
        }
    }
    dp(param, "======================================\n");
}
