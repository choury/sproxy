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

void test_vector_map_serialize() {
    using namespace bpf_detail;

    Server srv;
    srv.port = 8080;
    srv.ips = {"127.0.0.1", "10.0.0.1"};
    srv.config = {{"host", "localhost"}, {"mode", "debug"}};

    // Test serialization: just verify it doesn't crash and produces non-empty output
    auto t = std::tie(srv);
    std::vector<std::string> names = {"srv"};
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

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr<<"require args: <bpf_elf_path>"<<std::endl;
        return -1;
    }

    // --- Vector/Map serialize test ---
    test_vector_map_serialize();

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

    // BPF program verifies error codes then sets b = a * 100:
    //   bpf_kv_set("nonexistent",...) → checks -ENOENT
    //   bpf_kv_set("a", ..., STRING)  → checks -EINVAL
    //   If both pass, sets b = a * 100
    //   Returns non-zero on any failure (b unchanged)
    int a = 5, b = 20;
    int bpf_result = bpf_test_func(a, b);
    std::cout << "BPF test: a=" << a << " b=" << b << " result=" << bpf_result << std::endl;

    // bpf_test_func returns a + b.
    // If all BPF error-code checks pass: b = 500, result = 5 + 500 = 505
    // If any check fails: BPF returns early, b stays 20, result = 25
    if (bpf_result == 505) {
        std::cout << "BPF test PASSED" << std::endl;
    } else {
        std::cerr << "BPF test FAILED: expected 505, got " << bpf_result << std::endl;
        return 1;
    }

    hookManager.Unregister(bpf_hook);

    return 0;
}
