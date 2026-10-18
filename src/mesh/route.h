#ifndef ROUTE_H__
#define ROUTE_H__

#include "common/common.h"
#include "misc/config.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

constexpr int MESH_MAX_HOPS = 5;
//多跳路径每跳附加的固定代价(ms)：省出的 RTT 须超过罚时才胜出，
//抑制探测噪声下的近似平局翻转，以及各节点视图短暂不一致时的互相指环
constexpr double MESH_HOP_PENALTY = 5.0;
//条目/上报的新鲜度窗口(ms)，兼作节点间时钟偏差容忍
constexpr uint64_t MESH_FRESHNESS_MS = 120'000;
//rproxy 出口宣告边的固定权值(ms)：出口只有宣告节点一条可达路径，
//rtt 无选路意义，取正值以区别于死边(0)
constexpr double MESH_RPROXY_RTT_MS = 50.0;
//判死阈值：探测与 sync 失败都累积，仅成功清零
constexpr int MESH_FAIL_DEAD = 3;
constexpr uint32_t MESH_BACKOFF_CAP_MS = 300'000; //失败退避上限
//换轨滞回带(ms)：候选须优于活跃线路超过此值才切换，抑制探测噪声下来回翻转
constexpr double MESH_SWITCH_MARGIN_MS = 10.0;
//DNS 重解析间隔上限(ms)，实际取记录 ttl 夹在 [探测周期, 此值]
constexpr uint64_t MESH_DNS_RETRY_MAX_MS = 3'600'000;

//失败退避的下一档：首档取 base，之后倍增至封顶
constexpr uint32_t mesh_next_backoff(uint32_t cur, uint32_t base) {
    uint32_t next = cur ? cur * 2u : base;
    return next > MESH_BACKOFF_CAP_MS ? MESH_BACKOFF_CAP_MS : next;
}

struct MeshRoutePath {
    std::string first_hop;
    double cost = 0;
    int hops = 0;
};

//单条线路(键="宣告地址|IP")：addr 钉住该 IP(端口取宣告地址的)；
//探测状态是探测方本地状态，不随宣告序列化
struct AddrProbe {
    sockaddr_storage addr{};  //线路IP，含端口
    double rtt = 0;
    int fails = 0;
    uint32_t backoff = 0;
    uint64_t next_try = 0;
};

//节点表条目：seeded 表示来自 --mesh-peer 静态种子，
struct MeshEntry {
    uint32_t caps = 0;
    uint64_t ts = 0;     //源节点宣告时间(ms)，宣告与邻边共用此新鲜度
    bool seeded = false;
    std::set<std::string> addrs;             //宣告地址集合
    std::vector<sockaddr_storage> ips;       //最近一次解析结果,不含端口
    std::map<std::string, AddrProbe> paths;  //ip线路表
    std::string active;                      //最优线路的key，空=未选定
    uint64_t dns_retry = 0;                  //下次dns解析的时间
    double cost = 0;     //与自身的活边权值(ms)，0=非邻居或已判死
    std::map<std::string, double> edges; //该节点上报的它的邻边(仅活边)：对端 -> 边权
    uint32_t ok = 0, fail = 0; //探测成功/失败累计
    bool syncing = false;

    [[nodiscard]] bool fresh(uint64_t now) const {
        return seeded || now <= ts + MESH_FRESHNESS_MS;
    }
};

//在值线路可用(未判死且有成功样本)时的查询入口：边权与连接目标共用此守卫，
//保证路由决策与数据面实际转发的线路一致
inline const AddrProbe* mesh_alive_path(const MeshEntry& e) {
    auto it = e.paths.find(e.active);
    if(it == e.paths.end() || it->second.fails >= MESH_FAIL_DEAD || it->second.rtt == 0) {
        return nullptr;
    }
    return &it->second;
}

inline double mesh_edge_cost(const MeshEntry& e) {
    const AddrProbe* path = mesh_alive_path(e);
    return path ? path->rtt : 0;
}

inline void mesh_failover(MeshEntry& e) {
    e.active.clear();
    for(auto& [key, lp] : e.paths) {
        lp.next_try = 0;
    }
}

//宣告地址集 × 解析结果重建线路表；active线路消失则触发全量重选
void mesh_rebuild_paths(MeshEntry& e);

//按线路键前段的宣告地址现算连接参数并钉住线路IP(键两段都不含 '|')；
//hostname 即节点名，承载 SNI/证书校验
Destination mesh_path_dest(const std::string& key, const sockaddr_storage& addr);

bool mesh_route(const std::string& self, const std::map<std::string, MeshEntry>& table,
                const std::string& target, MeshRoutePath& out);

bool mesh_pick_exit(const std::string& self, const std::map<std::string, MeshEntry>& table,
                    std::string& exit_name, MeshRoutePath& out);

#endif
