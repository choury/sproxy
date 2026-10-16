#ifndef ROUTE_H__
#define ROUTE_H__

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
//判死阈值：地址连续失败次数(探测与 sync 失败都累积，仅探测成功清零)，
//达阈值判死——活边权值归 0、启动探测退避
constexpr int MESH_FAIL_DEAD = 3;
constexpr uint32_t MESH_BACKOFF_CAP_MS = 300'000; //失败退避上限

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

//地址探测状态：rtt=最近成功rtt(ms)且0=无样本；fails=连续失败(≥MESH_FAIL_DEAD
//判死，只影响选址不再排除探测)；判死后退避：backoff 倍增至 MESH_BACKOFF_CAP_MS，
//next_try 前不再探测。全 0 为"已宣告未探测"哨兵——真实探测必产生 rtt>0 或 fails>0。
//键(宣告地址)与宣告序列化不含探测状态：探测是探测方本地状态
struct AddrProbe {
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
    //键=宣告的地址；值=该地址探测状态
    std::map<std::string, AddrProbe> addrs;
    double cost = 0;     //与自身的活边权值(ms)，0=非邻居或已判死
    std::map<std::string, double> edges; //该节点上报的它的邻边(仅活边)：对端 -> 边权
    uint32_t ok = 0, fail = 0; //探测成功/失败累计
    bool syncing = false;

    [[nodiscard]] bool fresh(uint64_t now) const {
        return seeded || now <= ts + MESH_FRESHNESS_MS;
    }
};

bool mesh_route(const std::string& self, const std::map<std::string, MeshEntry>& table,
                const std::string& target, MeshRoutePath& out);

bool mesh_pick_exit(const std::string& self, const std::map<std::string, MeshEntry>& table,
                    std::string& exit_name, MeshRoutePath& out);

#endif
