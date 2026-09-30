#include "mesh_manager.h"

#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"
#include "res/responser.h"
#include "res/host.h"

#include <string.h>
#include <inttypes.h>

MeshManager* MeshManager::instance = nullptr;

//剥除请求上所有 X-Mesh-* 头：入口注入前清除客户端伪造的头，
//出口/凭据无效时防止 mesh 内部头透传到目标站
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

//数据面凭据带 identifier（最终出口名），控制面凭据不带
static bool isMeshCredit(const char* auth, bool need_identifier, struct Credit* cr) {
    return auth && decodeauth(auth, cr)
           && strcmp(cr->user, "mesh") == 0
           && (!need_identifier || cr->identifier[0])
           && checksecret(auth, cr);
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
        strcpy(dest.credit.user, "mesh");
        snprintf(dest.credit.pass, sizeof(dest.credit.pass), "%s", opt.mesh_secret);
        dest.credit.identifier[0] = 0;
        instance->nodes.emplace(name, MeshNode{.dest = dest});
    }
    instance->probe_interval_ms = opt.mesh_probe_interval * 1000;
    instance->probePeers();
    instance->schedule_probe();
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
        return response(rw, HttpResHeader::create(S502, sizeof(S502), id),
                        "[[mesh: auto exit is not supported]]\n");
    }
    auto node_it = nodes.find(name);
    if(node_it == nodes.end()) {
        return response(rw, HttpResHeader::create(S502, sizeof(S502), id),
                        "[[mesh: unknown node]]\n");
    }
    // Phase 1 只有直连出口：dest 即出口节点，无中继
    Destination dest = node_it->second.dest;
    snprintf(dest.credit.identifier, sizeof(dest.credit.identifier), "%s", name.c_str());
    req->chain_proxy = true;
    req->set("Proxy-Authorization", encodeCredit(&dest.credit));
    req->set("X-Mesh-Exit", name);
    //Phase 1 无中继，hops 仅预埋，Phase 3 起由中继逐跳递减
    req->set("X-Mesh-Hops", opt.mesh_maxhops);
    LOGD(DMESH, "mesh dispatch: %s exit=%s direct\n", req->geturl().c_str(), name.c_str());
    Host::distribute(req, dest, rw);
}

bool MeshManager::forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    const char* auth = req->get("Proxy-Authorization");
    struct Credit cr{};
    // identifier（最终出口名）承载在凭据里，与头分离的伪造不进入 mesh 语义
    if(!isMeshCredit(auth, true, &cr)) {
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
    // Phase 1 不支持中继：收到发往其他节点的 mesh 请求即为配置错误
    response(rw, HttpResHeader::create(S502, sizeof(S502), req->request_id),
             "[[mesh: relay is not supported]]\n");
    return false;
}

void MeshManager::handle_local(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                               const std::string& filename) {
    uint64_t id = req->request_id;
    // /mesh/* 端点仅接受 mesh 凭据，普通代理用户与免认证通道不放行
    struct Credit cr{};
    if(!isMeshCredit(req->get("Proxy-Authorization"), false, &cr)) {
        auto sheader = HttpResHeader::create(S401, sizeof(S401), id);
        sheader->set("WWW-Authenticate", "Basic realm=\"mesh\"");
        return response(rw, sheader, "[[mesh: authorization required]]\n");
    }
    if(filename == "mesh/ping") {
        return response(rw, HttpResHeader::create(S200, sizeof(S200), id), "pong\n");
    }
    response(rw, HttpResHeader::create(S404, sizeof(S404), id), "[[mesh: unknown endpoint]]\n");
}

void MeshManager::schedule_probe() {
    probe_job = UpdateJob(std::move(probe_job), [this]{
        probePeers();
        schedule_probe();
    }, probe_interval_ms);
}

void MeshManager::probePeers() {
    for(auto& [name, node] : nodes) {
        if(inflight.count(name)) {
            continue; //上一次探测未返回
        }
        probe(name, node);
    }
}

void MeshManager::probe(const std::string& name, MeshNode& node) {
    // 探测请求经 peer 连接（responsers 连接池复用）直达对端，
    // 同时重臂连接的空闲计时；不依赖 Proxy2::ping_check（忙连接不发 PING）
    std::string pa = encodeCredit(&node.dest.credit);
    char buff[HEADLENLIMIT];
    int headlen = snprintf(buff, sizeof(buff),
                           "GET /mesh/ping HTTP/1.1" CRLF
                           "Host: localhost" CRLF
                           "Proxy-Authorization: %s" CRLF CRLF, pa.c_str());
    auto req = UnpackHttpReq(buff, headlen);
    uint64_t send_us = getutime();
    auto got_response = std::make_shared<bool>(false);
    //探测结束后必须向 Responser 发 CHANNEL_ABORT 回收流表项（同 Guest::deqReq 模式），
    //否则 h2 peer 的 statusmap 永不清理、h1 peer 每次 probe 泄漏一条连接。
    //MemRWer 可能仍在自身的事件调用栈内触发回调，释放必须延迟一拍（同 Proxy2::Clean 模式）
    auto finish = [this, name]{
        addjob_with_name([this, name]{
            auto it = inflight.find(name);
            if(it == inflight.end()) {
                return;
            }
            auto flight = std::move(it->second);
            inflight.erase(it);
            flight.rw->push_signal(Signal::CHANNEL_ABORT);
        }, "mesh probe finish", 0, JOB_FLAGS_AUTORELEASE);
    };
    auto cb = IMemRWerCallback::create();
    cb->onHeader([this, name, send_us, got_response](std::shared_ptr<HttpResHeader> res) {
        auto it = nodes.find(name);
        if(it == nodes.end()) {
            return;
        }
        *got_response = true;
        if(memcmp(res->status, "200", 3) != 0) {
            LOGE("(%s) mesh probe %s got %s\n", opt.mesh_name, name.c_str(), res->status);
            it->second.probe_fail++;
            return;
        }
        double rtt = (getutime() - send_us) / 1000.0;
        auto& node = it->second;
        node.rtt_ms = node.rtt_ms > 0 ? node.rtt_ms * 0.875 + rtt * 0.125 : rtt;
        node.last_ok_ms = getmtime();
        node.probe_ok++;
        LOGD(DMESH, "mesh probe %s: rtt=%.1fms\n", name.c_str(), rtt);
    })->onData([finish](Buffer&& bb) {
        if(bb.len == 0) {
            finish();
            return 0;
        }
        return (int)bb.len;
    })->onSignal([this, name, finish, got_response](Signal) {
        if(!inflight.count(name)) {
            return; //成功结束后回收触发的信号，不再计失败
        }
        //连接失败时 Host 会先以 503 应答触发 onHeader，随后的 abort 信号不重复计失败
        if(!*got_response) {
            auto it = nodes.find(name);
            if(it != nodes.end()) {
                it->second.probe_fail++;
            }
        }
        finish();
    })->onCap([]{
        return (size_t)BUF_LEN;
    })->onWrite([](uint64_t){});

    Destination local{};
    strcpy(local.hostname, "localhost");
    auto rw = std::make_shared<MemRWer>(local, req->Dest, cb);
    inflight.emplace(name, Inflight{rw, cb});
    Host::distribute(req, node.dest, rw);
}

void MeshManager::dump_stat(Dumper dp, void* param) {
    dp(param, "======================================\n");
    dp(param, "mesh node: %s, peers: %zu\n", opt.mesh_name, nodes.size());
    for(auto& [name, node] : nodes) {
        dp(param, "  %s [%s]: rtt=%.1fms probes=%" PRIu64 "/%" PRIu64 " last_ok=%s\n",
           name.c_str(), dumpDest(node.dest).c_str(), node.rtt_ms,
           node.probe_ok, node.probe_fail,
           node.last_ok_ms ? (std::to_string(getmtime() - node.last_ok_ms) + "ms ago").c_str() : "-");
    }
    dp(param, "======================================\n");
}
