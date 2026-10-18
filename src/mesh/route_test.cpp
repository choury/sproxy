#include "route.h"
#include "misc/net.h"

#include <arpa/inet.h>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>

//C 依赖的最小桩(与 buffer_test 同法)：单测不链接 misc，仅覆盖线路逻辑所需的解析与串化
extern "C" int parseDest(const char* proxy, Destination* dest) {
    memset(dest, 0, sizeof(*dest));
    const char* sep = strstr(proxy, "://");
    const char* colon = sep ? strrchr(sep + 3, ':') : nullptr;
    if(!sep || !colon) {
        return -1;
    }
    size_t slen = sep - proxy;
    size_t hlen = colon - (sep + 3);
    if(slen >= sizeof(dest->scheme) || hlen >= sizeof(dest->hostname)) {
        return -1;
    }
    memcpy(dest->scheme, proxy, slen);
    memcpy(dest->hostname, sep + 3, hlen);
    dest->port = atoi(colon + 1);
    if(strcmp(dest->scheme, "https") == 0) {
        strcpy(dest->protocol, "ssl");
    }else if(strcmp(dest->scheme, "http") == 0) {
        strcpy(dest->protocol, "tcp");
    }else{
        return -1;
    }
    return dest->port == 0 ? -1 : 0;
}

extern "C" const char* getaddrstring(const sockaddr_storage* addr) {
    static char buff[INET6_ADDRSTRLEN];
    if(addr->ss_family == AF_INET) {
        inet_ntop(AF_INET, &((const sockaddr_in*)addr)->sin_addr, buff, sizeof(buff));
    }else{
        inet_ntop(AF_INET6, &((const sockaddr_in6*)addr)->sin6_addr, buff, sizeof(buff));
    }
    return buff;
}

extern "C" int storage_aton(const char* ipstr, uint16_t port, sockaddr_storage* addr) {
    memset(addr, 0, sizeof(*addr));
    if(strchr(ipstr, ':')) {
        sockaddr_in6* a6 = (sockaddr_in6*)addr;
        a6->sin6_family = AF_INET6;
        if(inet_pton(AF_INET6, ipstr, &a6->sin6_addr) != 1) {
            return 0;
        }
        a6->sin6_port = htons(port);
    }else{
        sockaddr_in* a4 = (sockaddr_in*)addr;
        a4->sin_family = AF_INET;
        if(inet_pton(AF_INET, ipstr, &a4->sin_addr) != 1) {
            return 0;
        }
        a4->sin_port = htons(port);
    }
    return 1;
}

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

static sockaddr_storage mk_ip(const char* ip) {
    sockaddr_storage sa{};
    assert(storage_aton(ip, 0, &sa) == 1);
    return sa;
}

static uint16_t ip_port(const AddrProbe& lp) {
    return ntohs(((sockaddr_in6*)&lp.addr)->sin6_port);
}

int main(){
    MeshRoutePath p;
    std::string exit_name;

    std::cout<<"---------- t1: linear chain ----------"<<std::endl;
    {
        Fixture f("A");
        f.node("B").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("C").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("D").caps = MESH_CAP_EXIT;
        f.node("B").cost = 1.0;
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
        f.node("n1").cost = 1.0;
        for(int i = 1; i <= 6; i++) {
            char name[8], next[8];
            snprintf(name, sizeof(name), "n%d", i);
            snprintf(next, sizeof(next), "n%d", i + 1);
            f.node(name).caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
            f.node(name).edges = {{next, 1.0}};
        }
        assert(mesh_route(f.self, f.table, "n5", p) && p.hops == 5 && p.first_hop == "n1");
        assert(!mesh_route(f.self, f.table, "n6", p)); //6 跳超过上限
    }

    std::cout<<"---------- t3: relay cap on transit node ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("m").caps = MESH_CAP_RELAY;
        f.node("x").caps = 0; //无 relay：只能当终点
        f.node("e").caps = MESH_CAP_EXIT;
        f.node("m").cost = 1.0;
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
        f.node("n").cost = 5.0;
        assert(mesh_route(f.self, f.table, "far", p) && p.first_hop == "n");
        f.node("n").cost = 0; //判死
        assert(!mesh_route(f.self, f.table, "far", p));
    }

    std::cout<<"---------- t5: pick exit ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("r").caps = MESH_CAP_RELAY;
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("y").caps = MESH_CAP_EXIT;
        f.node("z").caps = MESH_CAP_RELAY; //更近但无 exit 位
        f.node("r").cost = 1.0;
        f.node("y").cost = 25.0;
        f.node("z").cost = 1.0;
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
        f.node("a").cost = 1.0;
        f.node("b").cost = 1.0;
        assert(mesh_pick_exit(f.self, f.table, exit_name, p));
        assert(exit_name == "a");
    }

    std::cout<<"---------- t7: report edges are undirected ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("p").caps = MESH_CAP_RELAY;
        f.node("q").caps = MESH_CAP_EXIT;
        f.node("p").cost = 1.0;
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
        f.node("a").cost = 1.0;
        f.node("c").cost = 11.0;
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
        f.node("n").cost = 3.0; //自己探测成功后才有边
        assert(mesh_route(f.self, f.table, "n", p) && p.first_hop == "n" && p.hops == 1);
        assert(mesh_route(f.self, f.table, "far", p) && p.first_hop == "n" && p.hops == 2);
    }

    std::cout<<"---------- t10: stale entries are excluded ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("n").cost = 1.0;
        f.node("n").seeded = false; //ts=0 且非种子：已过期
        assert(!mesh_route(f.self, f.table, "n", p));
    }

    std::cout<<"---------- t11: own edge weight takes min of both reports ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY;
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("n").cost = 5.0;
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
        f.node("n").cost = 0;
        f.node("n").edges["s"] = 0.1;
        assert(!mesh_route(f.self, f.table, "x", p));
    }

    std::cout<<"---------- t12: cheap path must not evict hop-rich states ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("n").caps = MESH_CAP_RELAY | MESH_CAP_EXIT;
        f.node("t").caps = MESH_CAP_EXIT;
        //直达 n：贵(100)但只 1 跳；绕行链便宜(边权和 0.5×5=2.5)且罚时后仍远低于直达
        f.node("n").cost = 100.0;
        f.node("c1").cost = 0.5;
        for(int i = 1; i <= 3; i++) {
            char name[8], next[8];
            snprintf(name, sizeof(name), "c%d", i);
            snprintf(next, sizeof(next), "c%d", i + 1);
            f.node(name).caps = MESH_CAP_RELAY;
            f.node(name).edges = {{next, 0.5}};
        }
        f.node("c4").caps = MESH_CAP_RELAY;
        f.node("c4").edges = {{"n", 0.5}};
        f.node("n").edges = {{"t", 0.1}};
        //n 自身取便宜长路；t 只能走"贵但跳数富余"的直达状态（5 跳状态再走即超限）
        assert(mesh_route(f.self, f.table, "n", p) && p.first_hop == "c1"
               && p.hops == 5 && std::fabs(p.cost - (2.5 + 5 * MESH_HOP_PENALTY)) < 1e-9);
        assert(mesh_route(f.self, f.table, "t", p) && p.first_hop == "n"
               && p.hops == 2 && std::fabs(p.cost - (100.1 + 2 * MESH_HOP_PENALTY)) < 1e-9);
    }

    std::cout<<"---------- t13: non-relay exits are never transited ----------"<<std::endl;
    {
        Fixture f("s");
        f.node("x").caps = MESH_CAP_EXIT; //出口但无 relay 位
        f.node("y").caps = MESH_CAP_EXIT;
        f.node("r").caps = MESH_CAP_RELAY;
        f.node("x").cost = 1.0;
        f.node("r").cost = 10.0;
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
        f.node("a").cost = 1.0;
        f.node("a").edges = {{"x", 1.9}};
        f.node("x").cost = 5.0; //两跳边权和 2.9 略小于直连 5，省出的差额不足一跳罚时：取直连
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "x" && p.hops == 1);
        f.node("x").cost = 30.0; //差额远超罚时：绕行胜出
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "a" && p.hops == 2);
    }

    std::cout<<"---------- t15: rproxy exit announced by relay ----------"<<std::endl;
    {
        Fixture f("c");
        //c 视角：x 是 r 宣告的 rproxy 出口——无宣告地址无探测，仅一条到 r 的固定权值边
        f.node("r").caps = MESH_CAP_RELAY;
        f.node("x").caps = MESH_CAP_EXIT;
        f.node("r").cost = 20.0;
        f.node("x").edges = {{"r", MESH_RPROXY_RTT_MS}};
        assert(mesh_route(f.self, f.table, "x", p) && p.first_hop == "r" && p.hops == 2);
        assert(std::fabs(p.cost - (20.0 + MESH_RPROXY_RTT_MS + 2 * MESH_HOP_PENALTY)) < 1e-9);
        assert(mesh_pick_exit(f.self, f.table, exit_name, p) && exit_name == "x");
        //宣告节点自身不经 mesh 路由到 x：无宣告地址无法落账首跳，走本地 rproxy 分发
        assert(!mesh_route("r", f.table, "x", p));
    }

    std::cout << "---------- t16: probe backoff ladder ----------" << std::endl;
    {
        //首档=base，之后倍增，封顶 MESH_BACKOFF_CAP_MS
        assert(mesh_next_backoff(0, 10'000) == 10'000);
        assert(mesh_next_backoff(10'000, 10'000) == 20'000);
        assert(mesh_next_backoff(200'000, 10'000) == MESH_BACKOFF_CAP_MS);
        assert(mesh_next_backoff(MESH_BACKOFF_CAP_MS, 10'000) == MESH_BACKOFF_CAP_MS);
    }

    std::cout << "---------- t17: line table rebuild ----------" << std::endl;
    {
        MeshEntry e;
        e.addrs = {"https://n:443", "http://n:80"};
        e.ips = {mk_ip("192.168.1.1"), mk_ip("fd00::2")};
        mesh_rebuild_paths(e);
        assert(e.paths.size() == 4);
        assert(e.paths.count("https://n:443|192.168.1.1"));
        assert(e.paths.count("http://n:80|fd00::2"));
        const AddrProbe& lp = e.paths.at("https://n:443|192.168.1.1");
        assert(lp.addr.ss_family == AF_INET);
        assert(ip_port(lp) == 443);
        assert(ip_port(e.paths.at("http://n:80|fd00::2")) == 80);
        Destination d = mesh_path_dest("https://n:443|192.168.1.1", lp.addr);
        assert(strcmp(d.hostname, "n") == 0); //SNI/证书校验仍用节点名
        assert(d.port == 443);
        assert(d.resolved_addr.ss_family == AF_INET);
        assert(strcmp(getaddrstring(&d.resolved_addr), "192.168.1.1") == 0);
        //同集重建：存活线路保留探测状态与在值
        e.paths.at("https://n:443|192.168.1.1").rtt = 20.0;
        e.active = "http://n:80|fd00::2";
        e.paths.at(e.active).rtt = 30.0;
        e.cost = 30.0;
        mesh_rebuild_paths(e);
        assert(e.paths.size() == 4);
        assert(e.paths.at("https://n:443|192.168.1.1").rtt == 20.0);
        assert(e.active == "http://n:80|fd00::2");
        assert(e.cost == 30.0); //在值存活：边权随重建重算不变
        //IP 消失带走在值线路：清空在值、边权同步归零、立即全量重选
        e.paths.at("https://n:443|192.168.1.1").next_try = 12345;
        e.ips = {mk_ip("192.168.1.1")};
        mesh_rebuild_paths(e);
        assert(e.paths.size() == 2);
        assert(e.active.empty());
        assert(e.cost == 0);
        for(const auto& [key, path] : e.paths) {
            assert(path.next_try == 0);
        }
        //坏宣告地址不产线路
        MeshEntry bad;
        bad.addrs = {"ftp://n:21"};
        bad.ips = {mk_ip("192.168.1.1")};
        mesh_rebuild_paths(bad);
        assert(bad.paths.empty());
    }

    std::cout << "---------- t18: takeover hysteresis ----------" << std::endl;
    {
        MeshEntry e;
        e.addrs = {"https://n:443"};
        e.ips = {mk_ip("192.168.1.1"), mk_ip("192.168.1.2")};
        mesh_rebuild_paths(e);
        //接管判定的本地复刻(生产逻辑内联在 probe_path 回调里)：候选 rtt 须优于
        //在值超过滞回带；在值缺失(未选定或被重建删掉)时直接上位
        auto takeover = [&e](const std::string& active, double rtt) {
            auto it = e.paths.find(active);
            return it == e.paths.end() || rtt + MESH_SWITCH_MARGIN_MS < it->second.rtt;
        };
        //无在值线路：任何活样本直接上位(故障快速恢复)
        assert(takeover("", 100.0));
        e.active = "https://n:443|192.168.1.1";
        e.paths.at(e.active).rtt = 50.0;
        //滞回带内不换轨
        assert(!takeover(e.active, 45.0));
        assert(!takeover(e.active, 40.0 + 1e-9));
        //优于在值超过滞回带才换轨
        assert(takeover(e.active, 39.9));
        //在值键已消失(线路被重建删掉)：直接上位
        assert(takeover("gone", 100.0));
    }

    std::cout << "---------- t19: failover reset ----------" << std::endl;
    {
        MeshEntry e;
        e.addrs = {"https://n:443"};
        e.ips = {mk_ip("192.168.1.1"), mk_ip("192.168.1.2")};
        mesh_rebuild_paths(e);
        e.active = "https://n:443|192.168.1.1";
        e.paths.at("https://n:443|192.168.1.1").next_try = 12345;
        e.paths.at("https://n:443|192.168.1.2").next_try = 67890;
        mesh_failover(e);
        assert(e.active.empty());
        for(const auto& [key, path] : e.paths) {
            assert(path.next_try == 0);
        }
    }

    std::cout << "---------- t20: edge cost from active line only ----------" << std::endl;
    {
        MeshEntry e;
        e.addrs = {"https://n:443"};
        e.ips = {mk_ip("192.168.1.1"), mk_ip("192.168.1.2")};
        mesh_rebuild_paths(e);
        //无在值线路：边权 0，即使备线有更优样本(备线平时不探测、不经数据面)
        e.paths.at("https://n:443|192.168.1.2").rtt = 10.0;
        assert(mesh_edge_cost(e) == 0);
        e.active = "https://n:443|192.168.1.1";
        e.paths.at(e.active).rtt = 50.0;
        assert(mesh_edge_cost(e) == 50.0);
        //在值判死：边权归 0，备线样本不顶替
        e.paths.at(e.active).fails = MESH_FAIL_DEAD;
        assert(mesh_edge_cost(e) == 0);
    }

    std::cout << "all mesh route tests passed" << std::endl;
    return 0;
}
