#include "route.h"

#include <limits>
#include <queue>

namespace MeshRoute {

//有向邻接表：仅上报者 → 对端方向的边（见 mesh_route.h 的方向性论证）
static std::map<std::string, std::map<std::string, double>> build_adjacency(
    const std::map<std::string, std::map<std::string, double>>& links,
    const std::set<std::string>& nodes) {
    std::map<std::string, std::map<std::string, double>> adj;
    for(auto& [reporter, peers] : links) {
        if(!nodes.count(reporter)) {
            continue; //未知上报者不参与路由
        }
        for(auto& [peer, rtt] : peers) {
            if(!nodes.count(peer) || rtt <= 0) {
                continue;
            }
            adj[reporter][peer] = rtt;
        }
    }
    return adj;
}

std::pair<std::string, double> shortest_path(
    const std::map<std::string, std::map<std::string, double>>& links,
    const std::string& from, const std::string& target,
    const std::set<std::string>& routable, size_t max_hops) {
    if(from == target || !routable.count(target)) {
        return {"", 0};
    }
    std::set<std::string> nodes = routable;
    nodes.insert(from);
    auto adj = build_adjacency(links, nodes);

    //Dijkstra over (节点, 跳数) 状态：max_hops 限制路径边数
    struct State {
        double cost;
        size_t hops;
        std::string node;
        //first hop 只在终点态回溯，这里记录直接前驱
        std::string prev;
        bool operator>(const State& o) const {
            return cost > o.cost;
        }
    };
    std::map<std::pair<std::string, size_t>, std::pair<double, std::string>> dist;
    std::priority_queue<State, std::vector<State>, std::greater<State>> pq;
    dist[{from, 0}] = {0, ""};
    pq.push({0, 0, from, ""});
    double best = std::numeric_limits<double>::max();
    std::pair<std::string, size_t> best_state;
    while(!pq.empty()) {
        State s = pq.top();
        pq.pop();
        auto key = std::make_pair(s.node, s.hops);
        if(dist.count(key) && dist[key].first < s.cost) {
            continue; //过期堆项
        }
        if(s.node == target && s.cost < best) {
            best = s.cost;
            best_state = key;
            continue; //target 无出边需求，后续堆项代价只会更大
        }
        if(s.hops >= max_hops) {
            continue;
        }
        for(auto& [next, w] : adj[s.node]) {
            double ncost = s.cost + w;
            if(ncost >= best) {
                continue;
            }
            auto nkey = std::make_pair(next, s.hops + 1);
            auto it = dist.find(nkey);
            if(it != dist.end() && it->second.first <= ncost) {
                continue;
            }
            dist[nkey] = {ncost, s.node};
            pq.push({ncost, s.hops + 1, next, s.node});
        }
    }
    if(best == std::numeric_limits<double>::max()) {
        return {"", 0};
    }
    //沿前驱链回溯：(from,0) 的直接后继即下一跳。
    //每个 (节点,跳数) 态的前驱在其定值时已最终化（Dijkstra 弹出序），链必完整
    std::string nexthop;
    auto cur = best_state;
    while(dist[cur].second != "") {
        std::string prev = dist[cur].second;
        if(prev == from) {
            nexthop = cur.first;
            break;
        }
        cur = {prev, cur.second - 1};
    }
    return {nexthop, best};
}

}
