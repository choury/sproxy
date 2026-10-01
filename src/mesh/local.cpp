#include "local.h"
#include "manager.h"
#include "gossip.h"
#include "misc/config.h"
#include "misc/strategy.h"
#include "misc/job.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"
#include "res/responser.h"

#include <assert.h>
#include <inttypes.h>

static MeshLocal* _mesh_local = nullptr;

MeshLocal::MeshLocal() {
    assert(_mesh_local == nullptr);
    _mesh_local = this;
}

MeshLocal::~MeshLocal() {
    assert(_mesh_local == this);
    _mesh_local = nullptr;
}

MeshLocal* MeshLocal::GetInstance() {
    if(_mesh_local == nullptr) {
        new MeshLocal();
    }
    return _mesh_local;
}

void MeshLocal::announce(uint64_t id) {
    auto it = statusmap.find(id);
    if(it == statusmap.end()) {
        return;
    }
    auto status = it->second;
    statusmap.erase(it);
    auto es = MeshGossip::parse_entries(status.data);
    if(es.empty()) {
        failed_count++;
        return response(status.rw, HttpResHeader::create(S400, sizeof(S400), id),
                        "[[mesh: bad entry]]\n");
    }
    auto [accepted, valid] = MeshManager::Instance()->learn_entries(std::move(es));
    (void)accepted; //announce 应答只看验签有效性
    if(valid == 0) {
        failed_count++;
        return response(status.rw, HttpResHeader::create(S400, sizeof(S400), id),
                        "[[mesh: entries rejected]]\n");
    }
    succeed_count++;
    response(status.rw, HttpResHeader::create(S200, sizeof(S200), id), "ok\n");
}

void MeshLocal::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    uint64_t id = req->request_id;
    // /mesh/* 端点仅接受 mesh 凭据，普通代理用户与免认证通道不放行
    struct Credit cr{};
    if(!MeshManager::CheckMeshCredit(req->get("Proxy-Authorization"), false, &cr)) {
        failed_count++;
        auto sheader = HttpResHeader::create(S401, sizeof(S401), id);
        sheader->set("WWW-Authenticate", "Basic realm=\"mesh\"");
        return response(rw, sheader, "[[mesh: authorization required]]\n");
    }
    if(req->ismethod("GET")) {
        if(req->filename == "mesh/ping") {
            return response(rw, HttpResHeader::create(S200, sizeof(S200), id), "pong\n");
        }
        if(req->filename == "mesh/hello") {
            //与 announce 携带的单条目一致，供人工诊断与预留的握手场景
            auto res = HttpResHeader::create(S200, sizeof(S200), id);
            res->set("Content-Type", "application/json");
            return response(rw, res, MeshManager::Instance()->own_entry_json());
        }
        if(req->filename == "mesh/nodes") {
            auto res = HttpResHeader::create(S200, sizeof(S200), id);
            res->set("Content-Type", "application/json");
            return response(rw, res, MeshManager::Instance()->export_entries_json());
        }
        if(req->filename == "mesh/metrics") {
            auto res = HttpResHeader::create(S200, sizeof(S200), id);
            res->set("Content-Type", "application/json");
            return response(rw, res, MeshManager::Instance()->own_metrics_json());
        }
        failed_count++;
        return response(rw, HttpResHeader::create(S404, sizeof(S404), id),
                        "[[mesh: unknown endpoint]]\n");
    }
    if(req->ismethod("POST") && req->filename == "mesh/announce") {
        auto _cb = IRWerCallback::create()->onError([this, id](int, int) {
            addjob_with_name([this, id]{statusmap.erase(id);},
                             "meshlocal clean", 0, JOB_FLAGS_AUTORELEASE);
        })->onClose([this, id]{
            statusmap.erase(id);
        })->onRead([this, id](Buffer&& bb) -> size_t {
            if(statusmap.count(id) == 0) {
                return bb.len;
            }
            if(bb.len == 0) {
                addjob_with_name([this, id]{announce(id);},
                                 "meshlocal announce", 0, JOB_FLAGS_AUTORELEASE);
                return 0;
            }
            //节点表条目很小，超长即恶意
            if(statusmap.at(id).data.size() + bb.len > 64 * 1024) {
                failed_count++;
                auto rw = statusmap.at(id).rw;
                statusmap.erase(id);
                response(rw, HttpResHeader::create(S413, sizeof(S413), id),
                         "[[payload too large]]\n");
                return bb.len;
            }
            statusmap.at(id).data.append((const char*)bb.data(), bb.len);
            return bb.len;
        });
        statusmap[id] = AnnStatus{req, rw, _cb, ""};
        rw->SetCallback(_cb);
        return;
    }
    failed_count++;
    response(rw, HttpResHeader::create(S404, sizeof(S404), id), "[[mesh: unknown endpoint]]\n");
}

void MeshLocal::dump_stat(Dumper dp, void* param) {
    dp(param, "meshlocal %p: announce ok=%" PRIu64 " failed=%" PRIu64 " pending=%zu\n",
       this, succeed_count, failed_count, statusmap.size());
}

void MeshLocal::dump_usage(Dumper dp, void* param) {
    dp(param, "meshlocal %p: %zd\n", this, sizeof(*this));
}
