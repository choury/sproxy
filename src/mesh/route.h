#ifndef ROUTE_H__
#define ROUTE_H__

#include "misc/config.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

constexpr int MESH_MAX_HOPS = 10;
//多跳路径每跳附加的固定代价(ms)：省出的 RTT 须超过罚时才胜出，
//抑制探测噪声下的近似平局翻转，以及各节点视图短暂不一致时的互相指环
constexpr double MESH_HOP_PENALTY = 5.0;
//条目/上报的新鲜度窗口(ms)，兼作节点间时钟偏差容忍
constexpr uint64_t MESH_FRESHNESS_MS = 120'000;

struct MeshRoutePath {
    std::string first_hop;
    double cost = 0;
    int hops = 0;
};

//节点表条目：seeded 表示来自 --mesh-peer 静态种子，
struct MeshEntry {
    uint32_t caps = 0;
    uint64_t ts = 0;     //源节点宣告时间(ms)，宣告与邻边共用此新鲜度
    bool seeded = false;
    //键=宣告的地址；值=该地址探测状态(最近成功rtt, 连续失败)，
    //(0,0) 为"已宣告未探测"哨兵——真实探测必产生 rtt>0 或 fails>0
    std::map<std::string, std::pair<double, int>> addrs;
    double rtt = 0;      //与自身的活边 rtt(ms)，0=非邻居或已判死
    std::map<std::string, double> edges; //该节点上报的它的邻边(仅活边)：对端 -> rtt
    uint32_t ok = 0, fail = 0; //探测成功/失败累计
    bool probing = false;
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
