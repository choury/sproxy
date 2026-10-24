#ifndef ROUTE_H__
#define ROUTE_H__

#include "common/common.h"
#include "misc/config.h"

#include <cstdint>
#include <map>
#include <memory>
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
//判死阈值：探测失败累积，仅成功清零
constexpr int MESH_FAIL_DEAD = 3;
constexpr uint32_t MESH_BACKOFF_CAP_MS = 300'000; //失败退避上限
//换轨滞回带(ms)：候选须优于活跃线路超过此值才切换，抑制探测噪声下来回翻转
constexpr double MESH_SWITCH_MARGIN_MS = 10.0;
//DNS 重解析间隔上限(ms)，实际取记录 ttl 夹在 [探测周期, 此值]
constexpr uint64_t MESH_DNS_RETRY_MAX_MS = 3'600'000;
//活跃线路重算周期(ms)：active 有效时直接沿用，到期才遍历重选
constexpr uint64_t MESH_PATH_REFRESH_MS = 120'000;

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

//单条线路：ip 固定住该 IP，端口取所属宣告地址的；
//探测状态是探测方本地状态，不随宣告序列化
struct MeshPath {
    sockaddr_storage ip{};    //线路IP，端口取宣告地址的
    double rtt = 0;    //平滑rtt，0=未测得/判死
    double rttvar = 0;
    int fails = 0;
    uint32_t backoff = 0;
    uint64_t next_try = 0;

    //组装连接参数；hostname 取宣告地址，承载 SNI/证书校验
    Destination getDest(const Addr& addr) const {
        Destination dest{};
        dest.addr = addr;
        dest.resolved_addr = ip;
        return dest;
    }

    //RTO 式预期时延：可靠传输下丢包表现为重传等待，计入方差而非失败
    double cost() const { return rtt + 4 * rttvar; }
    //收敛参数与 tcp/quic 的 RTO 估计一致(RFC6298)
    void sample(double rtt);
};

//一个宣告地址一个 endpoint：dns 按宣告地址的 hostname 发起，解析结果展开成线路表
struct MeshEndpoint {
    Addr addr{};              //宣告地址
    uint64_t dns_retry = 0;   //下次dns解析的时间
    uint64_t reselect_at = 0; //下次允许重算活跃线路的时间
    std::vector<std::shared_ptr<MeshPath>> paths;
    std::weak_ptr<MeshPath> active;         //本地址活跃线路，空=未选定

    std::shared_ptr<MeshPath> activePath();
};

//节点表条目：seeded 表示来自 --mesh-peer 静态种子，
struct MeshEntry {
    uint32_t caps = 0;
    uint64_t ts = 0;     //源节点宣告时间(ms)，宣告与邻边共用此新鲜度
    uint64_t reselect_at = 0; //下次允许重算选用地址的时间
    bool seeded = false;
    std::map<std::string, std::shared_ptr<MeshEndpoint>> endpoints; //宣告地址 -> endpoint
    std::weak_ptr<MeshEndpoint> active;         //选用的 endpoint，空=未选定
    std::map<std::string, double> edges; //该节点上报的它的邻边(仅活边)：对端 -> 边权
    bool syncing = false;

    [[nodiscard]] bool fresh(uint64_t now) const {
        return seeded || now <= ts + MESH_FRESHNESS_MS;
    }

    std::shared_ptr<MeshPath> activePath();

    //与自身的活边权值(ms)：活跃线路的代价，0=非邻居或已判死
    double cost() {
        std::shared_ptr<MeshPath> live = activePath();
        return live ? live->cost() : 0;
    }

    std::set<std::string> addrs() const;
    void setAddrs(const std::set<std::string>& addrs);
    //活跃线路的连接目的地(确定ip地址)；调用方以 cost()>0 保证有活跃线路
    Destination activeDest() const;
    std::string probeState() const;
};

bool mesh_route(const std::string& self, const std::map<std::string, std::shared_ptr<MeshEntry>>& table,
                const std::string& target, MeshRoutePath& out);

bool mesh_pick_exit(const std::string& self, const std::map<std::string, std::shared_ptr<MeshEntry>>& table,
                    std::string& exit_name, MeshRoutePath& out);

#endif
