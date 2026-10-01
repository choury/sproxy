#ifndef MESH_ROUTE_H__
#define MESH_ROUTE_H__

#include <map>
#include <set>
#include <string>
#include <utility>

//拓扑图与最短路（docs/mesh.md 6.2）。纯函数、无副作用，便于单测。
//图为有向：A→B 的边只来自 A 自己的探测上报——转发方向的数据由 A 发起，
//A 能拨通 B 才可经 B 转发。这使死节点的陈旧自宣（C→B）不会虚构出 B→C 边。
//links: 上报者 → (对端 → rtt ms)；routable: 可作为路径成员的节点名集合
namespace MeshRoute {

//从 from 到 target 的最短路。返回 {下一跳, 代价}；下一跳为空表示不可达。
//选出的下一跳天然满足 dist(下一跳→target) < dist(from→target)（4.3 防环递减规则）。
//路径长度（边数）超过 max_hops 视为不可达。
std::pair<std::string, double> shortest_path(
    const std::map<std::string, std::map<std::string, double>>& links,
    const std::string& from, const std::string& target,
    const std::set<std::string>& routable, size_t max_hops);

}

#endif
