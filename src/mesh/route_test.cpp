#include "route.h"

#include <cassert>
#include <cmath>
#include <cstdio>
#include <iostream>
#include <map>

struct Fixture {
    std::string self;
    std::map<std::string, MeshEntry> table;
    explicit Fixture(std::string s): self(std::move(s)) {}
    //经 node() 建的条目 seeded=永不过期，测试不用管时间
    MeshEntry& node(const std::string& n) {
        MeshEntry& e = table[n];
        e.seeded = true;
        return e;
    }
};

int main(){
    MeshRoutePath p;
    std::string exit_name;

    std::cout<<"---------- t1: linear chain ----------"<<std::endl;
    {
        Fixture f("A");
        f.node("B").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("C").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("D").caps = MESH_CAP_EXIT;
        f.node("B").rtt = 1.0;
        f.node("B").edges = {{"C", 2.0}};
        f.node("C").edges = {{"D", 4.0}};
        assert(mesh_route(f.self, f.table, "D", p));
        assert(p.first_hop == "B");
        assert(p.hops == 3);
        assert(std::fabs(p.cost - (7.0 + 3 * MESH_HOP_PENALTY)) < 1e-9);
        assert(mesh_route(f.self, f.table, "C", p) && p.first_hop == "B" && p.hops == 2);
        //自身与未知目标
        assert(!mesh_route(f.self, f.table, "A", p));
        assert(!mesh_route(f.self, f.table, "Z", p));
    }

    std::cout<<"---------- t2: max hops ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n1").rtt = 1.0;
        for(int i = 1; i <= 12; i++) {
            char name[8], next[8];
            snprintf(name, sizeof(name), "n%d", i);
            snprintf(next, sizeof(next), "n%d", i + 1);
            f.node(name).caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
            f.node(name).edges = {{next, 1.0}};
        }
        assert(mesh_route(f.self, f.table, "n9", p) && p.hops == 9 && p.first_hop == "n1");
        assert(mesh_route(f.self, f.table, "n10", p) && p.hops == 10);
        assert(!mesh_route(f.self, f.table, "n11", p)); //11 跳超过上限
    }

    std::cout<<"---------- t3: relay cap on transit node ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("m").caps = MESH_CAP_RELAY;
        f.node("x").caps = 0; //无 relay：只能当终点
        f.node("e").caps = MESH_CAP_EXIT;
        f.node("m").rtt = 1.0;
        f.node("m").edges = {{"x", 1.0}};
        f.node("x").edges = {{"e", 1.0}};
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "m" && p.hops == 2);
        assert(!mesh_route(f.self, f.table, "e", p)); //途经 x 需 relay
        f.node("x").caps = MESH_CAP_RELAY;
        assert(mesh_route(f.self, f.table, "e", p) && p.hops == 3 && p.first_hop == "m");
    }

    std::cout<<"---------- t4: self edge required / dead edge ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("far").caps = MESH_CAP_EXIT;
        f.node("n").edges = {{"far", 1.0}};
        assert(!mesh_route(f.self, f.table, "far", p)); //无自身出边
        f.node("n").rtt = 5.0;
        assert(mesh_route(f.self, f.table, "far", p) && p.first_hop == "n");
        f.node("n").rtt = 0; //判死
        assert(!mesh_route(f.self, f.table, "far", p));
    }

    std::cout<<"---------- t5: pick exit ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("r").caps = MESH_CAP_RELAY;
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("y").caps = MESH_CAP_EXIT;
        f.node("z").caps = MESH_CAP_RELAY; //更近但无 exit 位
        f.node("r").rtt = 1.0;
        f.node("y").rtt = 25.0;
        f.node("z").rtt = 1.0;
        f.node("r").edges = {{"x", 1.0}}; //x 两跳 2+罚时，y 直连 25+罚时，z 直连最近但无 exit 位
        assert(mesh_pick_exit(f.self, f.table, exit_name, p));
        assert(exit_name == "x" && std::fabs(p.cost - (2.0 + 2 * MESH_HOP_PENALTY)) < 1e-9
               && p.first_hop == "r");
        f.node("r").edges = {}; //x 失联
        assert(mesh_pick_exit(f.self, f.table, exit_name, p));
        assert(exit_name == "y" && p.first_hop == "y");
        f.node("x").caps = 0;
        f.node("y").caps = 0;
        assert(!mesh_pick_exit(f.self, f.table, exit_name, p)); //无 exit 候选
    }

    std::cout<<"---------- t6: deterministic tie-break ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("a").caps = MESH_CAP_EXIT;
        f.node("b").caps = MESH_CAP_EXIT;
        f.node("a").rtt = 1.0;
        f.node("b").rtt = 1.0;
        assert(mesh_pick_exit(f.self, f.table, exit_name, p));
        assert(exit_name == "a");
    }

    std::cout<<"---------- t7: report edges are undirected ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("p").caps = MESH_CAP_RELAY;
        f.node("q").caps = MESH_CAP_EXIT;
        f.node("p").rtt = 1.0;
        f.node("q").edges = {{"p", 2.0}}; //q 探测到 p，反向可用
        assert(mesh_route(f.self, f.table, "q", p) && p.first_hop == "p" && p.hops == 2);
    }

    std::cout<<"---------- t8: detour around non-relay node ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("a").caps = MESH_CAP_RELAY;
        f.node("x").caps = 0; //捷径中点不可中继
        f.node("c").caps = MESH_CAP_RELAY;
        f.node("t").caps = MESH_CAP_EXIT;
        f.node("a").rtt = 1.0;
        f.node("c").rtt = 11.0;
        f.node("a").edges = {{"x", 1.0}};
        f.node("x").edges = {{"t", 1.0}}; //s-a-x-t 边权和 3 但 x 不可中继
        f.node("c").edges = {{"t", 1.0}}; //s-c-t 边权和 12，罚时后仍低于绕行 s-a-x-t
        assert(mesh_route(f.self, f.table, "t", p) && p.first_hop == "c"
               && std::fabs(p.cost - (12.0 + 2 * MESH_HOP_PENALTY)) < 1e-9);
        f.node("x").caps = MESH_CAP_RELAY;
        assert(mesh_route(f.self, f.table, "t", p) && p.first_hop == "a"
               && std::fabs(p.cost - (3.0 + 3 * MESH_HOP_PENALTY)) < 1e-9);
    }

    std::cout<<"---------- t9: report edge incident to self is ignored ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        //自己探测 n 已判死，但 n 的陈旧上报仍声称 n-s 活着——不得复活该邻接
        f.node("n").edges = {{"s", 1.0}, {"far", 2.0}};
        f.node("far").caps = MESH_CAP_EXIT;
        assert(!mesh_route(f.self, f.table, "n", p));
        assert(!mesh_route(f.self, f.table, "far", p));
        f.node("n").rtt = 3.0; //自己探测成功后才有边
        assert(mesh_route(f.self, f.table, "n", p) && p.first_hop == "n" && p.hops == 1);
        assert(mesh_route(f.self, f.table, "far", p) && p.first_hop == "n" && p.hops == 2);
    }

    std::cout<<"---------- t10: stale entries are excluded ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("n").rtt = 1.0;
        f.node("n").seeded = false; //ts=0 且非种子：已过期
        assert(!mesh_route(f.self, f.table, "n", p));
    }

    std::cout<<"---------- t11: own edge weight takes min of both reports ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY;
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("n").rtt = 5.0;
        f.node("n").edges = {{"x", 5.0}};
        //自己测得 5ms，n 上报到我 1ms：自身边权值须与全网一致取 1ms，
        //否则我按 5ms 绕行而他节点按 1ms 直发，互指成环
        f.node("n").edges["s"] = 1.0;
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "n"
               && std::fabs(p.cost - (6.0 + 2 * MESH_HOP_PENALTY)) < 1e-9);
        f.node("n").edges.erase("s");
        assert(mesh_route(f.self, f.table, "x", p)
               && std::fabs(p.cost - (10.0 + 2 * MESH_HOP_PENALTY)) < 1e-9); //无对端上报时用自身测量
        //上报边再小也不能独立复活未探测/已判死的自身边（存在性只认自己的探测）
        f.node("n").rtt = 0;
        f.node("n").edges["s"] = 0.1;
        assert(!mesh_route(f.self, f.table, "x", p));
    }

    std::cout<<"---------- t12: cheap path must not evict hop-rich states ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("t").caps = MESH_CAP_EXIT;
        //直达 n：贵(100)但只 1 跳；绕行链便宜(边权和 0.5×10=5)且罚时后仍远低于直达
        f.node("n").rtt = 100.0;
        f.node("c1").rtt = 0.5;
        for(int i = 1; i <= 8; i++) {
            char name[8], next[8];
            snprintf(name, sizeof(name), "c%d", i);
            snprintf(next, sizeof(next), "c%d", i + 1);
            f.node(name).caps = MESH_CAP_RELAY;
            f.node(name).edges = {{next, 0.5}};
        }
        f.node("c9").caps = MESH_CAP_RELAY;
        f.node("c9").edges = {{"n", 0.5}};
        f.node("n").edges = {{"t", 0.1}};
        //n 自身取便宜长路；t 只能走"贵但跳数富余"的直达状态（10 跳状态再走即超限）
        assert(mesh_route(f.self, f.table, "n", p) && p.first_hop == "c1"
               && p.hops == 10 && std::fabs(p.cost - (5.0 + 10 * MESH_HOP_PENALTY)) < 1e-9);
        assert(mesh_route(f.self, f.table, "t", p) && p.first_hop == "n"
               && p.hops == 2 && std::fabs(p.cost - (100.1 + 2 * MESH_HOP_PENALTY)) < 1e-9);
    }

    std::cout<<"---------- t13: non-relay exits are never transited ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("x").caps = MESH_CAP_EXIT; //出口但无 relay 位
        f.node("y").caps = MESH_CAP_EXIT;
        f.node("r").caps = MESH_CAP_RELAY;
        f.node("x").rtt = 1.0;
        f.node("r").rtt = 10.0;
        f.node("x").edges = {{"y", 0.5}}; //y 经 x 仅 1.5，但 x 不可中继
        f.node("r").edges = {{"y", 1.0}}; //y 经 r 要 11
        //被途经的 x 自身（1.0）必比途经它到 y（1.5）便宜，选出的不能是途经 x 的 y
        assert(mesh_pick_exit(f.self, f.table, exit_name, p) && exit_name == "x" && p.first_hop == "x");
        //显式到 y 也不得途经非 relay 的 x，只能绕 r
        assert(mesh_route(f.self, f.table, "y", p) && p.first_hop == "r"
               && std::fabs(p.cost - (11.0 + 2 * MESH_HOP_PENALTY)) < 1e-9);
    }

    std::cout<<"---------- t14: hop penalty suppresses near-tie detour ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("a").caps = MESH_CAP_RELAY;
        f.node("a").rtt = 1.0;
        f.node("a").edges = {{"x", 1.9}};
        f.node("x").rtt = 5.0; //两跳边权和 2.9 略小于直连 5，省出的差额不足一跳罚时：取直连
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "x" && p.hops == 1);
        f.node("x").rtt = 30.0; //差额远超罚时：绕行胜出
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "a" && p.hops == 2);
    }

    std::cout << "all mesh route tests passed" << std::endl;
    return 0;
}
