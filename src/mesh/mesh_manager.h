#ifndef MESH_MANAGER_H__
#define MESH_MANAGER_H__

#include "common/common.h"
#include "misc/job.h"

#include <map>
#include <memory>
#include <string>

class HttpReqHeader;
class MemRWer;
struct IMemRWerCallback;

//mesh 目标在策略 ext 中的 scheme 前缀
#define MESH_SCHEME "mesh://"

struct MeshNode {
    Destination dest;        // 到该节点的出站目的地（凭据固定为 mesh 用户）
    double   rtt_ms = 0;     // 探测 RTT 的 EWMA（毫秒），0 表示尚无样本
    uint64_t probe_ok = 0;
    uint64_t probe_fail = 0;
    uint64_t last_ok_ms = 0; // 最近一次探测成功时间（getmtime），0 表示从未成功
};

class MeshManager {
public:
    static bool Started();
    static MeshManager* Instance();
    static void Start(); // server 启动时调用；未配置 mesh 时为空操作

    // distribute 的 proxy 分支拦截到 mesh:// ext 后调用，总是接管请求（转发或应答）
    static void Dispatch(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                         const std::string& ext);
    // distribute 的 mesh 前置步骤，请求携带 X-Mesh-Exit 时调用。
    // 返回 true 表示请求继续走正常流程（本节点是出口且已剥除 mesh 标记，
    // 或凭据无效仅剥头）；返回 false 表示已应答，调用方直接返回。
    static bool Forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);
    // mesh://<本节点名> 的出口即本机，distribute 据此归一化为 direct 策略
    static bool IsSelfExit(const char* name);
    // 请求携带任意 X-Mesh-* 头（含仅伪造 Hops 的情况），distribute 前置步骤的门条件
    static bool HasMeshHeaders(std::shared_ptr<HttpReqHeader> req);

    // /mesh/* 本地端点（File::getfile 分发），总是自行应答
    void handle_local(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                      const std::string& filename);

    void dump_stat(Dumper dp, void* param);

private:
    MeshManager() = default;
    void dispatch(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                  const std::string& ext);
    bool forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);

    void schedule_probe();
    void probePeers();
    void probe(const std::string& name, MeshNode& node);

    //MemRWer 只持回调的 weak_ptr，cb 必须自持到探测结束
    struct Inflight {
        std::shared_ptr<MemRWer> rw;
        std::shared_ptr<IMemRWerCallback> cb;
    };

    std::map<std::string, MeshNode> nodes;
    std::map<std::string, Inflight> inflight;
    Job probe_job = nullptr;
    uint32_t probe_interval_ms = 10000;

    static MeshManager* instance;
};

#endif
