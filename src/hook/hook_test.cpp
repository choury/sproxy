#include "hook.h"

#include <iostream>
#include <map>
#include <stdarg.h>
#include <assert.h>
#include <libgen.h>
#include <string.h>

extern "C" void slog(int level, const char* fmt, ...){
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

class Test{
    std::string hello = "Hello from Test!";
public:
    template <typename Visitor>
    void reflect(Visitor& v) const {
        v("hello", hello);
    }

    int operator()(int a, double b) {
        HOOK_FUNC(this, a, b, 10);
        HOOK_BPF(this, a);
        return a + b;
    }
    void sayHello() {
        std::cout << hello << std::endl;
    }
};

void test_func(std::string str) {
    HOOK_FUNC(str);
    std::cout << "test_func called with: " << str << std::endl;
}

int bpf_test_func(int a, int b) {
    HOOK_BPF(a, b);
    return a + b;
}

struct Server {
    int port;
    std::vector<std::string> ips;
    std::map<std::string, std::string> config;

    template <typename Visitor>
    void reflect(Visitor& v) const {
        v("port", port);
        v("ips", ips);
        v("config", config);
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
    bool ok = set_tuple_field(names, "srv.port", kv_port, t, std::index_sequence_for<Server&>{});
    assert(ok && srv.port == 9090);
    std::cout << "  set srv.port=9090: OK (got " << srv.port << ")" << std::endl;

    // Test write-back: modify vector element
    BpfKV kv_ip = BpfKV::make_string("192.168.1.1");
    ok = set_tuple_field(names, "srv.ips[0]", kv_ip, t, std::index_sequence_for<Server&>{});
    assert(ok && srv.ips[0] == "192.168.1.1");
    std::cout << "  set srv.ips[0]=\"192.168.1.1\": OK (got " << srv.ips[0] << ")" << std::endl;

    // Test write-back: modify existing map entry
    BpfKV kv_host = BpfKV::make_string("example.com");
    ok = set_tuple_field(names, "srv.config[host]", kv_host, t, std::index_sequence_for<Server&>{});
    assert(ok && srv.config["host"] == "example.com");
    std::cout << "  set srv.config[host]=\"example.com\": OK (got " << srv.config["host"] << ")" << std::endl;

    // Test write-back: add new map key
    BpfKV kv_new = BpfKV::make_string("/var/log");
    ok = set_tuple_field(names, "srv.config[logdir]", kv_new, t, std::index_sequence_for<Server&>{});
    assert(ok && srv.config["logdir"] == "/var/log");
    std::cout << "  set srv.config[logdir]=\"/var/log\": OK (got " << srv.config["logdir"] << ")" << std::endl;

    // Test write-back: vector out-of-bounds should fail
    ok = set_tuple_field(names, "srv.ips[99]", kv_ip, t, std::index_sequence_for<Server&>{});
    assert(!ok);
    std::cout << "  set srv.ips[99]: correctly rejected" << std::endl;

    std::cout << "Vector/Map test PASSED" << std::endl;
}

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr<<"require args: <so_path> [bpf_elf_path]"<<std::endl;
        return -1;
    }

    // --- LibCallback test ---
    const void* where = nullptr;
    for(auto& [hook, msg]: hookManager.GetHookers()) {
        std::cout << hook <<": " << msg << std::endl;
        if(msg.find("Test::operator()") != std::string::npos) {
            where = hook;
        }
    }
    // 注册回调
    std::string msg;
    auto callback = std::make_shared<LibCallback>(argv[1], msg);
    if(!msg.empty()) {
        std::cerr << "Failed to create callback: " << msg << std::endl;
    }
    assert(msg.empty());
    hookManager.Register(where, callback);

    // 调用函数
    Test test;
    int result = test(5, 3);
    std::cout << "Result: " << result << std::endl;

    test_func("Hello, World!");

    // 移除回调
    hookManager.Unregister(where);
    for(auto& [hook, msg]: hookManager.GetHookers()) {
        std::cout << hook <<": " << msg << std::endl;
    }

    // --- Vector/Map serialize test ---
    test_vector_map_serialize();

    // --- BPF test ---
    std::string bpf_elf_path;
    if (argc >= 3) {
        bpf_elf_path = argv[2];
    } else {
        // Try to find hook_bpf.elf in same directory as the test binary
        char buf[4096];
        strncpy(buf, argv[0], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        std::string dir = dirname(buf);
        bpf_elf_path = dir + "/hook_bpf.elf";
    }

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

    // Call bpf_test_func(5, 20) - BPF program should set b = a * 100 = 500
    int a = 5, b = 20;
    int bpf_result = bpf_test_func(a, b);
    std::cout << "BPF test: a=" << a << " b=" << b << " result=" << bpf_result << std::endl;

    // The BPF program sets b = a * 100. Since a=5, b should become 500 inside bpf_test_func.
    // bpf_test_func returns a + b, so result should be 5 + 500 = 505
    // Note: b in main() is not modified since bpf_test_func takes b by value
    if (bpf_result == 505) {
        std::cout << "BPF test PASSED" << std::endl;
    } else {
        std::cerr << "BPF test FAILED: expected result=505, got result=" << bpf_result << std::endl;
        return 1;
    }

    hookManager.Unregister(bpf_hook);

    return 0;
}
