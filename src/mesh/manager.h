#ifndef MANAGER_H__
#define MANAGER_H__

#include "common/common.h"
#include "mesh/route.h"
#include "misc/job.h"
#include "misc/strategy.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#define MESH_SCHEME "mesh://"

class MeshManager {
    std::vector<std::string> self_addrs;
    struct Credit mesh_credit{};
    uint32_t probe_ms = 0;
    uint32_t sync_ms = 0;
    Job probe_job;
    Job sync_job;
    std::map<std::string, MeshEntry> table; //不含自身
    std::string last_auto_exit;
    struct SyncStatus {
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer> rw;
        std::shared_ptr<IRWerCallback> cb;
        std::string data;
    };
    std::map<uint64_t, SyncStatus> sync_reqs; //POST /mesh/nodes 收包中

    MeshManager();
    void probe_round();
    void sync_round();
    std::string serialize() const;
    void merge(const std::string& body);
    const std::string& best_addr(const MeshEntry& e) const;
    
public:
    static void Start();
    static MeshManager* GetInstance();
    //mesh 分发决策：none=未知目标(404 兜底)；direct=本机出口；
    //proxy 且 dest->port!=0=发往下一跳(hostname=下一跳节点名，credit=逐跳凭据)；
    //proxy 且 port==0=错误页，ext 为文案(502)
    static strategy Route(const std::string& target, Destination* dest);
    void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);
    void dump(Dumper dp, void* param);
};

void dump_mesh(Dumper dp, void* param);

#endif
