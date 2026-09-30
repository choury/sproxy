#include "mesh_gossip.h"

#include <assert.h>
#include <iostream>
#include <string.h>

static MeshEntry build_entry() {
    MeshEntry e;
    e.name = "node-a.example.com";
    e.addrs = {"https://node-a.example.com:443", "quic://node-a.example.com:443"};
    e.caps = {"exit"};
    e.seen = 1727654000;
    return e;
}

int main() {
    const char* secret = "test-secret";

    //签名/验签往返与篡改检测
    MeshEntry e = build_entry();
    MeshGossip::sign_entry(e, secret);
    assert(MeshGossip::verify_entry(e, secret));
    e.seen++;
    assert(!MeshGossip::verify_entry(e, secret));
    MeshGossip::sign_entry(e, secret);
    assert(!MeshGossip::verify_entry(e, "other-secret"));

    //规范化串确定性：相同内容两次签名一致
    MeshEntry e2 = build_entry();
    MeshGossip::sign_entry(e2, secret);
    MeshEntry e3 = build_entry();
    MeshGossip::sign_entry(e3, secret);
    assert(e2.sig == e3.sig);

    //新鲜度窗口：双向
    int64_t now = e.seen;
    assert(MeshGossip::fresh_entry(e, now));
    assert(MeshGossip::fresh_entry(e, now + 300));
    assert(MeshGossip::fresh_entry(e, now - 300));
    assert(!MeshGossip::fresh_entry(e, now + 301));
    assert(!MeshGossip::fresh_entry(e, now - 301));

    //结构校验：addrs 主机名必须等于节点名
    assert(MeshGossip::valid_entry(e));
    MeshEntry bad = e;
    bad.addrs = {"https://attacker.io:443"};
    assert(!MeshGossip::valid_entry(bad));
    bad = e;
    bad.name = "node+bad";
    assert(!MeshGossip::valid_entry(bad));
    bad = e;
    bad.addrs = {"not a url"};
    assert(!MeshGossip::valid_entry(bad));
    //纯入口节点（无 addrs）合法
    bad = e;
    bad.addrs.clear();
    assert(MeshGossip::valid_entry(bad));

    //JSON 往返
    std::string json = MeshGossip::entry_to_json(e);
    auto es = MeshGossip::parse_entries(json);
    assert(es.size() == 1);
    assert(es[0].name == e.name && es[0].addrs == e.addrs && es[0].caps == e.caps
           && es[0].seen == e.seen && es[0].sig == e.sig);
    assert(MeshGossip::verify_entry(es[0], secret));

    //数组解析与坏输入
    std::string arr = MeshGossip::entries_to_json({e, e2});
    assert(MeshGossip::parse_entries(arr).size() == 2);
    assert(MeshGossip::parse_entries("not json").empty());
    assert(MeshGossip::parse_entries("{\"name\":\"x\"}").empty());

    //能力位
    assert(e.has_cap("exit"));
    assert(!e.has_cap("relay"));

    //name/via 字符集：分隔符字符与歧义字符被拒
    MeshEntry tok = e;
    tok.via = "node_b.example.com";
    assert(MeshGossip::valid_entry(tok));
    tok.via = "bad via";
    assert(!MeshGossip::valid_entry(tok));
    tok.via = "a,b";
    assert(!MeshGossip::valid_entry(tok));
    tok = e;
    tok.name = "a\nb";
    assert(!MeshGossip::valid_entry(tok));

    //单对象（announce 请求体形态）解析成功
    MeshEntry single = build_entry();
    single.seen = 999;
    MeshGossip::sign_entry(single, secret);
    auto single_es = MeshGossip::parse_entries(MeshGossip::entry_to_json(single));
    assert(single_es.size() == 1 && single_es[0].seen == 999);
    //字段残缺的对象解析失败
    assert(MeshGossip::parse_entries("{\"addrs\":[\"https://a\"]}").empty());

    //addrs 的端口/路径剥离后主机名须等于节点名
    MeshEntry addr = e;
    addr.addrs = {"https://node-a.example.com:8443/some?path"};
    assert(MeshGossip::valid_entry(addr));
    addr.addrs = {"https://user@node-a.example.com:8443"};
    assert(!MeshGossip::valid_entry(addr)); // userinfo 不属于主机名

    std::cout << "mesh_gossip test PASSED" << std::endl;
    return 0;
}
