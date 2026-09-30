#ifndef MESH_MANAGER_H__
#define MESH_MANAGER_H__

#include "common/common.h"
#include "misc/job.h"
#include "mesh_gossip.h"

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>

class HttpReqHeader;
class MemRWer;
struct IMemRWerCallback;

//mesh 目标在策略 ext 中的 scheme 前缀
#define MESH_SCHEME "mesh://"

struct MeshNode {
    Destination dest;      // 到该节点的出站目的地（凭据固定为 mesh 用户）
    std::string url;       // 静态配置的原始 URL（gossip 条目则为 addrs[0]）
    MeshEntry entry;       // gossip 条目（静态配置节点为空）
    bool is_static = false;
    bool exit_cap = true;  // 静态配置节点缺省可做出口
    double   rtt_ms = 0;   // 探测 RTT 的 EWMA（毫秒），0 表示尚无样本
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
    // mesh 凭据判定：数据面带 identifier（最终出口名），控制面不带
    static bool CheckMeshCredit(const char* auth, bool need_identifier, struct Credit* cr);

    // /mesh/* 端点（MeshLocal 分发）使用的查询
    std::string own_entry_json();
    std::string export_entries_json();
    std::string own_metrics_json();
    // 自身链路状态（有向，与判活同口径）
    LinkReport own_metrics();
    // 合并收到的链路状态（按上报时间戳过期，未知上报者忽略）
    void learn_metrics(std::vector<LinkReport> reports);
    // 合并收到的条目（校验签名/新鲜度/结构），发现新节点即加入探测；
    // 返回 {采纳数, 验签有效数}，announce 以此区分 200（含合法但非更新）与 400
    std::pair<size_t, size_t> learn_entries(std::vector<MeshEntry> es);

    void dump_stat(Dumper dp, void* param);

private:
    MeshManager() = default;
    void dispatch(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw,
                  const std::string& ext);
    bool forward(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);

    //发一次控制面请求，done 在收到完整响应或失败时各调一次
    void request(const Destination& dest,
                 const char* method, const char* path, const std::string& body,
                 std::function<void(int status, std::string resbody)> done);

    void schedule_probe();
    void probePeers();
    void probe(const std::string& name, MeshNode& node);

    void schedule_gossip();
    void gossip_cycle();
    void expire_learned();
    const MeshEntry& own_entry();
    //到出口的路由（含滞回）：组图（自身探测 + 收到的链路状态）后跑最短路。
    //返回下一跳（== exit 即直连），不可达返回空串；cost_out 可空
    std::string route_to(const std::string& exit_name, double* cost_out = nullptr);
    //mesh://auto 出口选择（含滞回），无可用出口返回空串
    std::string pick_auto_exit();
    //近期探测成功过（5 个探测周期内），失联节点的残留 rtt 不可信
    bool alive(const MeshNode& node) const;

    //MemRWer 只持回调的 weak_ptr，cb 必须自持到请求结束
    struct Inflight {
        std::shared_ptr<MemRWer> rw;
        std::shared_ptr<IMemRWerCallback> cb;
    };

    std::map<std::string, MeshNode> nodes;
    std::set<std::string> probe_inflight;
    std::map<uint64_t, Inflight> ctl_inflight;
    uint64_t ctl_seq = 1;
    //收到的链路状态：上报者 → (对端 → rtt)；link_ts 为上报的 Unix 秒（泛洪原样携带）
    std::map<std::string, std::map<std::string, double>> link_states;
    std::map<std::string, int64_t> link_ts;
    //每出口的路由滞回缓存（cost 为当前图下所选路径的实时代价）
    struct RouteChoice {
        std::string nexthop;
        double cost = 0;
    };
    std::map<std::string, RouteChoice> route_cache;
    Job probe_job = nullptr;
    Job gossip_job = nullptr;
    size_t gossip_offset = 0;
    uint32_t probe_interval_ms = 10000;
    uint32_t gossip_interval_ms = 30000;
    MeshEntry self_entry;
    //auto 出口的滞回状态
    std::string auto_exit;
    double auto_rtt = 0;
    uint64_t auto_switch_ms = 0;

    static MeshManager* instance;
};

#endif
