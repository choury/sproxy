#include "mesh_manager.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"
#include "res/responser.h"
#include "res/host.h"

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
    // Phase 2 只有直连出口：dest 即出口节点，无中继
    Destination dest = node_it->second.dest;
    snprintf(dest.credit.identifier, sizeof(dest.credit.identifier), "%s", name.c_str());
    req->chain_proxy = true;
    req->set("Proxy-Authorization", encodeCredit(&dest.credit));
    req->set("X-Mesh-Exit", name);
    //Phase 2 无中继，hops 仅预埋，Phase 3 起由中继逐跳递减
    req->set("X-Mesh-Hops", opt.mesh_maxhops);
    LOGD(DMESH, "mesh dispatch: %s exit=%s direct\n", req->geturl().c_str(), name.c_str());
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
    // Phase 2 不支持中继：收到发往其他节点的 mesh 请求即为配置错误
    response(rw, HttpResHeader::create(S502, sizeof(S502), req->request_id),
             "[[mesh: relay is not supported]]\n");
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
    std::vector<MeshEntry> es;
    es.push_back(own_entry());
    int64_t now = time(NULL);
    for(auto& [name, node] : nodes) {
        if(node.entry.seen != 0) {
            //已有该节点自宣的条目（含静态互联的），原样转发其签名条目；
            //不新鲜的不再扩散（peer 可能已死）
            if(MeshGossip::fresh_entry(node.entry, now)) {
                es.push_back(node.entry);
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
        e.seen = time(NULL);
        MeshGossip::sign_entry(e, opt.mesh_secret);
        es.push_back(e);
    }
    return MeshGossip::entries_to_json(es);
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
            if(e.seen <= it->second.entry.seen) {
                continue; //合法但非更新
            }
            if(it->second.is_static) {
                //静态优先仅限地址（dest/url 不被覆盖），能力与新鲜度照常学习，
                //否则 --mesh-exit=off 对静态互联的邻居永不生效
                it->second.entry = e;
                it->second.exit_cap = e.has_cap("exit");
                accepted++;
                continue;
            }
            if(it->second.entry.addrs != e.addrs) {
                //同名条目在仍新鲜时变更地址：命名冲突可能性，按设计放弃后到者；
                //真实迁移靠旧条目 TTL 过期后自然收敛
                LOGE("(%s) mesh: entry %s changed addrs while fresh, keep stored\n",
                     opt.mesh_name, e.name.c_str());
                continue;
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
                learn_entries(MeshGossip::parse_entries(body));
            }
        });
        request(it->second.dest, "POST", "/mesh/announce", own,
                [name](int status, std::string) {
            LOGD(DMESH, "mesh announce to %s: %d\n", name.c_str(), status);
        });
    }
    gossip_offset = (gossip_offset + batch) % names.size();
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
        it = nodes.erase(it);
    }
}

std::string MeshManager::pick_auto_exit() {
    uint64_t now = getmtime();
    //存活 = 近期探测成功过（5 个探测周期内），失联节点的残留 rtt 不参与选择
    auto alive = [&](const MeshNode& n) {
        return n.exit_cap && n.last_ok_ms != 0
               && now - n.last_ok_ms < (uint64_t)probe_interval_ms * 5;
    };
    std::string best;
    double best_rtt = 0;
    for(auto& [name, node] : nodes) {
        if(!alive(node)) {
            continue;
        }
        if(best.empty() || node.rtt_ms < best_rtt) {
            best = name;
            best_rtt = node.rtt_ms;
        }
    }
    if(best.empty()) {
        auto_exit.clear();
        return "";
    }
    auto cur = nodes.find(auto_exit);
    bool cur_alive = cur != nodes.end() && alive(cur->second);
    //切换滞回：现任失联立即切；否则需新路径比现任实时代价改善超过 20% 且距上次切换 >30s
    double cur_rtt = cur_alive ? cur->second.rtt_ms : 0;
    if(auto_exit.empty() || !cur_alive
       || (best != auto_exit && best_rtt < cur_rtt * 0.8
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
    dp(param, "======================================\n");
}
