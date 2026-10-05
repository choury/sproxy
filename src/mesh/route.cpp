#include "route.h"

#include <algorithm>
#include <chrono>
#include <queue>

namespace {

uint64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
}

void dijkstra(const std::string& self, const std::map<std::string, MeshEntry>& table,
              const std::set<std::string>& terminals,
              std::map<std::string, MeshRoutePath>& reach) {
    uint64_t now = now_ms();
    //邻接表：边的存在性只认自己的探测(首跳须自己验证，对端陈旧上报不得复活
    //已判死邻接)，但权值与全网一致取两端上报的最小值——若各节点对同一条边
    //各用各的私有测量，独立最短路计算会互指成环
    std::map<std::string, std::map<std::string, double>> adj;
    for(const auto& [peer, e] : table) {
        if(!e.fresh(now) || e.rtt <= 0) {
            continue;
        }
        double w = e.rtt;
        if(auto it = e.edges.find(self); it != e.edges.end()) {
            w = std::min(w, it->second);
        }
        adj[self][peer] = w;
    }
    for(const auto& [reporter, e] : table) {
        if(reporter == self || !e.fresh(now)) {
            continue;
        }
        for(const auto& [peer, rtt] : e.edges) {
            if(peer == self || rtt <= 0) {
                continue;
            }
            //两端各自上报同一链路时取较小者，消除处理顺序依赖
            auto& a1 = adj[reporter][peer];
            a1 = a1 > 0 ? std::min(a1, rtt) : rtt;
            auto& a2 = adj[peer][reporter];
            a2 = a2 > 0 ? std::min(a2, rtt) : rtt;
        }
    }
    auto caps_of = [&](const std::string& name) -> uint32_t {
        auto it = table.find(name);
        return (it == table.end() || !it->second.fresh(now)) ? 0u : it->second.caps;
    };

    using State = std::pair<std::string, int>;
    using Item = std::pair<double, State>;
    std::priority_queue<Item, std::vector<Item>, std::greater<Item>> pq;
    std::map<State, double> dist{{State{self, 0}, 0.0}};
    std::map<State, State> pred;
    pq.emplace(0.0, State{self, 0});

    while(!pq.empty()) {
        auto [d, state] = pq.top();
        pq.pop();
        if(d > dist.at(state)) {
            continue;
        }
        //非 relay 节点可入不可扩：只能作为终点，不得作为中间跳
        if(state.first != self && !(caps_of(state.first) & MESH_CAP_RELAY)) {
            continue;
        }
        auto it = adj.find(state.first);
        if(it == adj.end()) {
            continue;
        }
        for(const auto& [next, w] : it->second) {
            if(next == self) {
                continue;
            }
            //途经节点须可中继；终点不受限
            if(!(caps_of(next) & MESH_CAP_RELAY) && !terminals.count(next)) {
                continue;
            }
            int nhops = state.second + 1;
            if(nhops > MESH_MAX_HOPS) {
                continue;
            }
            double nd = d + w + MESH_HOP_PENALTY;
            State ns{next, nhops};
            auto dit = dist.find(ns);
            if(dit != dist.end() && dit->second <= nd) {
                continue;
            }
            dist[ns] = nd;
            pred[ns] = state;
            pq.emplace(nd, ns);
        }
    }

    //每节点取代价最小状态，平局取跳数少
    std::map<std::string, State> best;
    for(const auto& [state, d] : dist) {
        if(state.first == self) {
            continue;
        }
        auto [it, inserted] = best.emplace(state.first, state);
        if(!inserted && (d < dist.at(it->second) ||
                         (d == dist.at(it->second) && state.second < it->second.second)))
        {
            it->second = state;
        }
    }
    for(const auto& [name, state] : best) {
        State cur = state;
        while(pred.at(cur).first != self) {
            cur = pred.at(cur);
        }
        reach.emplace(name, MeshRoutePath{cur.first, dist.at(state), state.second});
    }
}

} //namespace

bool mesh_route(const std::string& self, const std::map<std::string, MeshEntry>& table,
                const std::string& target, MeshRoutePath& out) {
    if(target == self) {
        return false;
    }
    std::map<std::string, MeshRoutePath> reach;
    dijkstra(self, table, {target}, reach);
    auto it = reach.find(target);
    if(it == reach.end()) {
        return false;
    }
    out = it->second;
    return true;
}

bool mesh_pick_exit(const std::string& self, const std::map<std::string, MeshEntry>& table,
                    std::string& exit_name, MeshRoutePath& out) {
    uint64_t now = now_ms();
    std::set<std::string> terminals;
    for(const auto& [name, e] : table) {
        if(e.fresh(now) && (e.caps & MESH_CAP_EXIT)) {
            terminals.insert(name);
        }
    }
    if(terminals.empty()) {
        return false;
    }
    std::map<std::string, MeshRoutePath> reach;
    dijkstra(self, table, terminals, reach);
    bool found = false;
    //按名字序遍历保证平局时结果确定
    for(const auto& name : terminals) {
        auto it = reach.find(name);
        if(it == reach.end()) {
            continue;
        }
        if(!found || it->second.cost < out.cost) {
            out = it->second;
            exit_name = name;
            found = true;
        }
    }
    return found;
}
