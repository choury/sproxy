#ifndef MESH_MANAGER_H__
#define MESH_MANAGER_H__

#include "common/common.h"
#include "misc/config.h"
#include "misc/job.h"
#include "misc/strategy.h"
#include "gossip.h"

#include <map>
#include <set>
#include <string>

//mesh 目标在策略 ext 中的 scheme 前缀
#define MESH_SCHEME "mesh://"

struct MeshNode {
    Destination dest;      // 到该节点的出站目的地（凭据固定为 mesh 用户）
    std::string url;       // 静态配置的原始 URL（gossip 条目则为 addrs[0]）
    MeshEntry entry;       // gossip 条目（静态配置节点为空）
    bool is_static = false;
    //能力位（MESH_CAP_*）：静态配置节点缺省全能力，学习后被宣告值覆盖；0 = 入口节点
    uint32_t caps = MESH_CAP_EXIT | MESH_CAP_RELAY;
    double   rtt_ms = 0;   // 探测 RTT 的 EWMA（毫秒），0 表示尚无样本
    uint64_t probe_ok = 0;
    uint64_t probe_fail = 0;
    uint64_t last_ok_ms = 0; // 最近一次探测成功时间（getmtime），0 表示从未成功
};

class MeshManager {
public:
    static MeshManager* Instance();
    static void Start(); // server 启动时调用；未配置 mesh 时为空操作

    //mesh 纯路由：target 为节点名或 "auto"，不涉及认证、不构造应答；mesh 未启动返回 none。
    //{none}：非 mesh 目标，调用方继续后续解析；
    //{direct}：本节点即出口；
    //{proxy}：转发 *dest（credit 为逐跳凭据，identifier 已填最终目标，auto 的解析结果也在此）；
    //{proxy} 且 dest->port == 0：无路由/无出口，ext 即 502 应答 body
    static strategy Route(const std::string& target, Destination* dest);

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

private:
    MeshManager() = default;
    friend void dump_mesh(Dumper dp, void* param);

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

    std::map<std::string, MeshNode> nodes;
    std::set<std::string> probe_inflight;
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
    //控制面请求超时取 5×探测周期：h1 peer 无传输层保活，连接存活但不应答时靠此兜底回收
    uint32_t probe_interval_ms = 10000;
    uint32_t gossip_interval_ms = 30000;
    MeshEntry self_entry;
    //auto 出口的滞回状态
    std::string auto_exit;
    double auto_rtt = 0;
    uint64_t auto_switch_ms = 0;

    static MeshManager* instance;
};

void dump_mesh(Dumper dp, void* param);

#endif
