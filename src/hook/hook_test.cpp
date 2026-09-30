#include "hook.h"

#include <iostream>
#include <map>
#include <stdarg.h>
#include <assert.h>
#include <cerrno>

extern "C" void slog(int level, const char* fmt, ...){
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

int bpf_test_func(int a, int b) {
    HOOK_BPF(a, b);
    return a + b;
}

struct Server {
    int port;
    std::vector<std::string> ips;
    std::map<std::string, std::string> config;

    void reflect(IVisitor& v) {
        reflect_all(port, ips, config);
    }
};

static void bpf_srv_func(Server& srv) {
    HOOK_BPF(srv);
}

void test_vector_map_serialize() {
    using namespace bpf_detail;

    Server srv;
    srv.port = 8080;
    srv.ips = {"127.0.0.1", "10.0.0.1"};
    srv.config = {{"host", "localhost"}, {"mode", "debug"}};

    // Test serialization: just verify it doesn't crash and produces non-empty output
    auto t = std::tie(srv);
    constexpr Names<1> names{"srv"};
    std::string pb;
    serialize_tuple(pb, names, t, std::index_sequence_for<Server&>{});
    std::cout << "Vector/Map serialize: pb_data size=" << pb.size() << std::endl;
    assert(pb.size() > 0);

    // Test write-back: modify port via set_tuple_field
    BpfKV kv_port = BpfKV::make_int(9090);
    int r = set_tuple_field(names, "srv.port", kv_port, t, std::index_sequence_for<Server&>{});
    assert(r == 0 && srv.port == 9090);
    std::cout << "  set srv.port=9090: OK (got " << srv.port << ")" << std::endl;

    // Test write-back: modify vector element
    BpfKV kv_ip = BpfKV::make_string("192.168.1.1");
    r = set_tuple_field(names, "srv.ips[0]", kv_ip, t, std::index_sequence_for<Server&>{});
    assert(r == 0 && srv.ips[0] == "192.168.1.1");
    std::cout << "  set srv.ips[0]=\"192.168.1.1\": OK (got " << srv.ips[0] << ")" << std::endl;

    // Test write-back: modify existing map entry
    BpfKV kv_host = BpfKV::make_string("example.com");
    r = set_tuple_field(names, "srv.config[host]", kv_host, t, std::index_sequence_for<Server&>{});
    assert(r == 0 && srv.config["host"] == "example.com");
    std::cout << "  set srv.config[host]=\"example.com\": OK (got " << srv.config["host"] << ")" << std::endl;

    // Test write-back: add new map key
    BpfKV kv_new = BpfKV::make_string("/var/log");
    r = set_tuple_field(names, "srv.config[logdir]", kv_new, t, std::index_sequence_for<Server&>{});
    assert(r == 0 && srv.config["logdir"] == "/var/log");
    std::cout << "  set srv.config[logdir]=\"/var/log\": OK (got " << srv.config["logdir"] << ")" << std::endl;

    // Failed nested write must not auto-create a new map entry.
    size_t config_size = srv.config.size();
    r = set_tuple_field(names, "srv.config[missing].nested", kv_new, t, std::index_sequence_for<Server&>{});
    assert(r == -ENOENT && srv.config.size() == config_size && srv.config.count("missing") == 0);
    std::cout << "  set srv.config[missing].nested: correctly rejected with ENOENT" << std::endl;
    //r/config_size只在assert里使用，NDEBUG构建下消除unused告警
    (void)r;
    (void)config_size;

    // Test write-back: vector out-of-bounds should fail with EINVAL
    r = set_tuple_field(names, "srv.ips[99]", kv_ip, t, std::index_sequence_for<Server&>{});
    assert(r == -EINVAL);
    std::cout << "  set srv.ips[99]: correctly rejected with EINVAL" << std::endl;

    // Test write-back: nonexistent field should return ENOENT
    r = set_tuple_field(names, "nonexistent", kv_port, t, std::index_sequence_for<Server&>{});
    assert(r == -ENOENT);
    std::cout << "  set nonexistent: correctly rejected with ENOENT" << std::endl;

    // Test write-back: type mismatch should return EINVAL
    BpfKV kv_bad_type = BpfKV::make_string("not_an_int");
    r = set_tuple_field(names, "srv.port", kv_bad_type, t, std::index_sequence_for<Server&>{});
    assert(r == -EINVAL);
    std::cout << "  set srv.port=string: correctly rejected with EINVAL" << std::endl;

    std::cout << "Vector/Map test PASSED" << std::endl;
}

// 递归 reflect 的嵌套深度需超过 PBSerializeVisitor 的栈容量（64 层），
// 验证超深层按透明层降级而不是越界
struct DeepNode {
    int levels;
    void reflect(IVisitor& v) {
        int64_t leaf = levels;
        v.leaf_i64("leaf", leaf);
        if (levels <= 0) return;
        v.push("n");
        DeepNode child{levels - 1};
        child.reflect(v);
        v.pop();
    }
};

void test_deep_nest_serialize() {
    using namespace bpf_detail;

    DeepNode node{100};
    auto t = std::tie(node);
    constexpr Names<1> names{"node"};
    std::string pb;
    serialize_tuple(pb, names, t, std::index_sequence_for<DeepNode&>{});
    assert(pb.size() > 0);
    std::cout << "Deep nest serialize: pb_data size=" << pb.size() << std::endl;
    std::cout << "Deep nest test PASSED" << std::endl;
}

// 非相邻同前缀的点分参数名：编译期排序后应合并进同一层，不产生重复 key 条目
void test_dotted_name_merge() {
    using namespace bpf_detail;

    // Names 规整与排序本身
    constexpr Names<3> n{"a.x", " b ", "a.y"};
    static_assert(n.names[1][0] == 'b', "规整应去除空白");
    static_assert(n.perm[0] == 0 && n.perm[1] == 2 && n.perm[2] == 1, "排序序应为 a.x, a.y, b");
    static_assert(!n.has_prefix_conflict());
    constexpr Names<2> bad{"fdns", "fdns->statusmap"};
    static_assert(bad.names[1][4] == '.', "'->' 应规整为 '.'");
    static_assert(bad.has_prefix_conflict(), "祖先路径冲突应被检出");

    int x = 1, b = 2, y = 3;
    auto t = std::tie(x, b, y);

    std::string declaration_order;
    serialize_tuple(declaration_order, n, t, std::index_sequence_for<int&, int&, int&>{});

    std::string sorted;
    serialize_tuple(sorted, n, t,
        typename Permuted<n, std::index_sequence_for<int&, int&, int&>>::type{});

    // 顶层 KVMap 的 entry key 序列（field 1，LEN，tag 均为单字节）
    auto top_keys = [](const std::string& pb) {
        std::vector<std::string> keys;
        size_t pos = 0;
        while (pos < pb.size()) {
            assert(pb[pos] == 0x0a);  // MapEntry field 1, LEN
            size_t p = pos + 1, len = 0, shift = 0;
            while (true) {
                unsigned char c = pb[p++];
                len |= (size_t)(c & 0x7f) << shift;
                if (!(c & 0x80)) break;
                shift += 7;
            }
            size_t entry_end = p + len;
            assert(pb[p] == 0x0a);  // key field 1, LEN
            p++;
            size_t klen = 0;
            shift = 0;
            while (true) {
                unsigned char c = pb[p++];
                klen |= (size_t)(c & 0x7f) << shift;
                if (!(c & 0x80)) break;
                shift += 7;
            }
            keys.emplace_back(pb.substr(p, klen));
            pos = entry_end;
        }
        return keys;
    };

    auto k1 = top_keys(declaration_order);
    auto k2 = top_keys(sorted);
    assert((k1 == std::vector<std::string>{"a", "b", "a"}));  // 声明序：a 出现两次
    assert((k2 == std::vector<std::string>{"a", "b"}));       // 排序后：合并为一层
    assert(sorted.size() < declaration_order.size());
    std::cout << "Dotted-name merge: " << declaration_order.size() << " -> "
              << sorted.size() << " bytes, top keys merged" << std::endl;
    std::cout << "Dotted-name merge test PASSED" << std::endl;
}

// 空嵌套对象（push/pop 之间无叶子）不落线
struct Sparse {
    void reflect(IVisitor& v) {
        v.push("empty_sub");
        v.push("empty_inner");
        v.pop();
        v.pop();
        int64_t leaf = 7;
        v.leaf_i64("leaf", leaf);
    }
};

struct AllEmpty {
    void reflect(IVisitor& v) {
        v.push("a");
        v.push("b");
        v.pop();
        v.pop();
    }
};

void test_empty_object_dropped() {
    using namespace bpf_detail;

    Sparse obj;
    auto t = std::tie(obj);
    constexpr Names<1> names{"obj"};
    std::string pb;
    serialize_tuple(pb, names, t, std::index_sequence_for<Sparse&>{});
    assert(pb.find("empty_sub") == std::string::npos);
    assert(pb.find("empty_inner") == std::string::npos);
    assert(pb.find("leaf") != std::string::npos);

    AllEmpty empty;
    auto te = std::tie(empty);
    constexpr Names<1> empty_names{"e"};
    std::string pbe;
    serialize_tuple(pbe, empty_names, te, std::index_sequence_for<AllEmpty&>{});
    // Value 体为空（无 field 5），但仍落 entry { key: "e", value: {} }
    assert(pbe.find("e") != std::string::npos);
    assert(pbe.find("a") == std::string::npos);
    std::cout << "Empty object drop test PASSED" << std::endl;
}

// leaf_ro_*：const 引用入参的序列化路径
void test_readonly_leaves() {
    using namespace bpf_detail;

    std::string pb;
    PbWriter w(pb);
    PBSerializeVisitor sv(w);
    sv.push(nullptr);
    const std::string s = "readonly_str";
    const std::byte blob[4] = {};
    sv.leaf_ro_i64("ri", -5);
    sv.leaf_ro_u64("ru", 6);
    sv.leaf_ro_str("rs", s);
    sv.leaf_ro_blob("rb", blob, sizeof(blob));
    sv.pop();
    assert(pb.find("readonly_str") != std::string::npos);
    assert(pb.find("ri") != std::string::npos);
    assert(pb.find("ru") != std::string::npos);
    assert(pb.find("rb") != std::string::npos);
    std::cout << "Readonly leaves test PASSED" << std::endl;
}

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr<<"require args: <bpf_elf_path>"<<std::endl;
        return -1;
    }

    // --- Vector/Map serialize test ---
    test_vector_map_serialize();

    // --- Deep nesting serialize test ---
    test_deep_nest_serialize();

    // --- Dotted-name merge test ---
    test_dotted_name_merge();

    // --- Empty object drop test ---
    test_empty_object_dropped();

    // --- Readonly leaves test ---
    test_readonly_leaves();

    // --- BPF test ---
    std::string bpf_elf_path = argv[1];

    // Find the bpf_test_func hook point
    const void* bpf_hook = nullptr;
    // Trigger bpf_test_func once to register the hook point
    bpf_test_func(1, 2);
    for(auto& [hook, hmsg]: hookManager.GetHookers()) {
        if(hmsg.find("bpf_test_func") != std::string::npos) {
            bpf_hook = hook;
        }
    }

    if (!bpf_hook) {
        std::cerr << "BPF test: could not find bpf_test_func hook point" << std::endl;
        return 1;
    }

    std::string bpf_msg;
    auto bpf_cb = std::make_shared<BpfCallback>(bpf_elf_path, bpf_msg);
    if (!bpf_msg.empty()) {
        std::cerr << "BPF test: failed to create BpfCallback: " << bpf_msg << std::endl;
        return 1;
    }
    hookManager.Register(bpf_hook, bpf_cb);

    // BPF program verifies error codes then sets b = a * 100; bpf_test_func
    // returns a + b，全部校验通过时 b = 500、result = 505，否则 b 不变、result = 25。
    // 连续触发 3 次：vm::run() 退出时清空镜像，非首次触发验证镜像重装。
    for (int trigger = 1; trigger <= 3; trigger++) {
        int bpf_result = bpf_test_func(5, 20);
        std::cout << "BPF test: trigger " << trigger << " result=" << bpf_result << std::endl;
        if (bpf_result != 505) {
            std::cerr << "BPF test FAILED: expected 505, got " << bpf_result << std::endl;
            return 1;
        }
    }
    std::cout << "BPF test PASSED" << std::endl;

    hookManager.Unregister(bpf_hook);

    // --- 嵌套读写回环：BENCH_READBACK 变体读 srv 嵌套路径后写回 port+1000 ---
    std::string readback_elf = bpf_elf_path.substr(0, bpf_elf_path.find_last_of('/') + 1)
                             + "bench_readback.elf";
    std::string rb_msg;
    auto rb_cb = std::make_shared<BpfCallback>(readback_elf, rb_msg);
    if (!rb_msg.empty()) {
        std::cerr << "Readback test: failed to create BpfCallback: " << rb_msg << std::endl;
        return 1;
    }

    const void* srv_hook = nullptr;
    Server probe;
    bpf_srv_func(probe);
    for(auto& [hook, hmsg]: hookManager.GetHookers()) {
        if(hmsg.find("bpf_srv_func") != std::string::npos) {
            srv_hook = hook;
        }
    }
    if (!srv_hook) {
        std::cerr << "Readback test: could not find bpf_srv_func hook point" << std::endl;
        return 1;
    }

    Server srv;
    srv.port = 8080;
    srv.ips = {"127.0.0.1"};
    srv.config = {{"host", "localhost"}};
    hookManager.Register(srv_hook, rb_cb);
    bpf_srv_func(srv);
    hookManager.Unregister(srv_hook);
    if (srv.port != 9080) {
        std::cerr << "Readback test FAILED: expected port 9080, got " << srv.port << std::endl;
        return 1;
    }
    std::cout << "Readback test PASSED" << std::endl;

    return 0;
}
