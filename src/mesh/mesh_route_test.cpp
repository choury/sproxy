#include "mesh_route.h"

#include <assert.h>
#include <iostream>
#include <map>
#include <set>
#include <string>

typedef std::map<std::string, std::map<std::string, double>> Links;

int main() {
    //哑铃拓扑：A 只连 B；C 只连 D；B-D 为唯一桥接边（每条边两端各自上报）
    //  A --- B === D --- C
    // A 到 C 必须经 B、D 两跳中继
    Links dumbbell;
    dumbbell["A"] = {{"B", 2}};
    dumbbell["B"] = {{"A", 2}, {"D", 3}};
    dumbbell["C"] = {{"D", 4}};
    dumbbell["D"] = {{"B", 3}, {"C", 4}};
    std::set<std::string> routable = {"A", "B", "C", "D"};

    auto [nh, cost] = MeshRoute::shortest_path(dumbbell, "A", "D", routable, 4);
    assert(nh == "B");
    assert(cost == 5.0); // A-B(2) + B-D(3)

    //A 到 C：经 B、D 三跳
    std::tie(nh, cost) = MeshRoute::shortest_path(dumbbell, "A", "C", routable, 4);
    assert(nh == "B");
    assert(cost == 9.0); // A-B(2) + B-D(3) + D-C(4)

    //防环递减性质：对同一目标，下一跳的距离严格小于本节点的距离
    auto [nh_b, cost_b] = MeshRoute::shortest_path(dumbbell, "B", "C", routable, 4);
    assert(nh_b == "D" && cost_b == 7.0); // B-D(3) + D-C(4)
    assert(cost_b < cost); // A 选出的下一跳 B 到 C 严格更近

    //直连 vs 中继：直达稍慢于两跳串联时应选中继
    Links relay;
    relay["A"] = {{"B", 50}, {"D", 60}};
    relay["B"] = {{"A", 50}, {"D", 5}};
    relay["D"] = {{"A", 60}, {"B", 5}};
    std::tie(nh, cost) = MeshRoute::shortest_path(relay, "A", "D", {"A", "B", "D"}, 4);
    assert(nh == "B");
    assert(cost == 55.0);

    //直连明显更优时选直连（注意两端上报都要更新，双向边一致）
    relay["A"]["D"] = 10;
    relay["D"]["A"] = 10;
    std::tie(nh, cost) = MeshRoute::shortest_path(relay, "A", "D", {"A", "B", "D"}, 4);
    assert(nh == "D" && cost == 10.0);

    //有向性：死节点 C 的陈旧自宣（C→B）不能虚构出 B→C 边。
    //B 已把 C 从自己的上报中移除后，A 无法再经 B 到 C
    Links poison;
    poison["A"] = {{"B", 1}};
    poison["B"] = {{"A", 1}};             //B 的上报已不含 C
    poison["C"] = {{"B", 1}};             //C 死前的陈旧自宣
    std::set<std::string> pr = {"A", "B", "C"};
    std::tie(nh, cost) = MeshRoute::shortest_path(poison, "A", "C", pr, 4);
    assert(nh.empty());
    //A 的直连自宣始终有效，不受他人陈旧上报影响
    Links poison2;
    poison2["A"] = {{"B", 1}, {"C", 2}};
    poison2["B"] = {{"C", 1.5}};          //B 的陈旧上报
    std::tie(nh, cost) = MeshRoute::shortest_path(poison2, "A", "C", pr, 4);
    assert(nh == "C" && cost == 2.0);     //直连 2.0 < 经 B 2.5，无平手

    //不可达
    Links split;
    split["A"] = {{"B", 1}};
    split["C"] = {{"D", 1}};
    std::tie(nh, cost) = MeshRoute::shortest_path(split, "A", "D", {"A", "B", "C", "D"}, 4);
    assert(nh.empty());

    //跳数上限：链长超过 max_hops 不可达
    Links chain;
    chain["n1"] = {{"n2", 1}};
    chain["n2"] = {{"n1", 1}, {"n3", 1}};
    chain["n3"] = {{"n2", 1}, {"n4", 1}};
    chain["n4"] = {{"n3", 1}};
    std::set<std::string> cr = {"n1", "n2", "n3", "n4"};
    std::tie(nh, cost) = MeshRoute::shortest_path(chain, "n1", "n4", cr, 3);
    assert(nh == "n2" && cost == 3.0);
    std::tie(nh, cost) = MeshRoute::shortest_path(chain, "n1", "n4", cr, 2);
    assert(nh.empty());

    //未知上报者/未纳入 routable 的对端不参与路由
    Links stranger;
    stranger["A"] = {{"B", 1}};
    stranger["X"] = {{"A", 1}, {"C", 1}};
    std::tie(nh, cost) = MeshRoute::shortest_path(stranger, "A", "C", {"A", "B", "C"}, 4);
    assert(nh.empty());

    //目标即自身：无路径概念
    std::tie(nh, cost) = MeshRoute::shortest_path(dumbbell, "A", "A", routable, 4);
    assert(nh.empty());

    //rtt<=0 的上报视作无边（探测无样本）
    Links dead;
    dead["A"] = {{"B", 0}};
    std::tie(nh, cost) = MeshRoute::shortest_path(dead, "A", "B", {"A", "B"}, 4);
    assert(nh.empty());

    std::cout << "mesh_route test PASSED" << std::endl;
    return 0;
}
