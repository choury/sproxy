#include "hook.h"

#include <iostream>
#include <stdarg.h>
#include <assert.h>

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
    int operator()(int a, double b) {
        HOOK_FUNC(this, a, b);
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

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr<<"require args of lib path"<<std::endl;
        return -1;
    }
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
    return 0;

}
