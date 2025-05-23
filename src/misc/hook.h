#ifndef HOOK_H__
#define HOOK_H__
#include "common/common.h"

#include <memory>
#include <tuple>
#include <unordered_map>
#include <set>
#include <functional>
#include <string>
#include <dlfcn.h>
#include <stdarg.h>

// 一个通用的 Hook 回调接口示例，让用户自行决定如何处理 tuple 内的参数
class IHookCallback {
public:
    virtual ~IHookCallback() = default;
    virtual void OnCall(void* args) = 0;
    virtual std::string name() = 0;
};

//example:
// auto [testObj, firstArg, secondArg] = get_args<Test*, int, double>(args);
template <typename... Args>
auto get_args(void* args) -> std::tuple<Args&...> {
    // 将 void* 转换为 std::tuple<Args...>*，然后解引用并返回引用元组
    return *static_cast<std::tuple<Args&...>*>(args);
}

// Hook 管理器，用于注册和移除回调，并在需要时触发
class HookManager{
public:
    HookManager();
    // 注册回调
    void Register(const void* hooker, std::shared_ptr<IHookCallback> cb) {
        LOG("hooker registered: %p\n", hooker);
        callbacks.emplace(hooker, cb);
    }

    // 移除回调
    bool Unregister(const void* hooker) {
        if(callbacks.count(hooker) == 0) {
            return false; // 没有注册的回调
        }
        LOG("hooker unregistered: %p\n", hooker);
        callbacks.erase(hooker);
        return true;
    }

    template <typename... Args>
    void Trigger(const void* hooker, Args&&... args) {
        if(callbacks.count(hooker) == 0) {
            return; // 没有注册的回调
        }
        auto t = std::tie(args...);
        callbacks[hooker]->OnCall(&t);
    }

    bool AddHooker(bool* hooker, std::string func, const char* line) {
        hookers[hooker] = func + ":" + line;
        return *hooker = true;
    }

    const std::unordered_map<const void*, std::string>& GetHookers() const {
        return hookers;
    }

    void dump(Dumper dp, void* param) {
        dp(param, "Hookers:\n");
        for(const auto& [hooker, msg]: hookers) {
            dp(param, "  %p: %s\n", hooker, msg.c_str());
        }
        dp(param, "Callbacks:\n");
        for(const auto& [hooker, cb] : callbacks) {
            dp(param, "  %p: %s\n", hooker, cb->name().c_str());
        }
    }
private:
    std::unordered_map<const void*, std::shared_ptr<IHookCallback>> callbacks;
    std::unordered_map<const void*, std::string> hookers;
};

extern HookManager hookManager;

extern "C" void hook_callback(void* args);
#define CALLBACK_FUNCNAME "hook_callback"
// 加载动态库和获取函数指针作为回调
class LibCallback : public IHookCallback {
public:
    LibCallback(const std::string& so_path, std::string& msg) : so_path(so_path) {
        msg = "";
        handle = dlopen(so_path.c_str(), RTLD_NOW);
        if (!handle) {
            msg = std::string("dlopen failed: ") + dlerror();
            return;
        }
        callback = (void (*)(void*))dlsym(handle, CALLBACK_FUNCNAME);
        if (!callback) {
            msg = std::string("dlsym failed: ") + dlerror();
            return;
        }
    }

    ~LibCallback() {
        // 卸载动态库的逻辑
        if(handle) {
            dlclose(handle);
        }
        callback = nullptr;
    }
    void OnCall(void* args) override {
        // 调用动态库中的函数的逻辑
        if(!callback) {
            return;
        }
        callback(args);
    }
    std::string name() override {
        return so_path;
    }
private:
    const std::string so_path;
    void* handle = nullptr;
    void (*callback)(void*) = nullptr;
};

#define __S3(a, b, c) a##b##c
#define _S3(a, b, c) __S3(a, b, c)

#define HOOK_ADD(hooker, ...)  \

#define HOOK_FUNC(...) \
    static bool  _S3(__, __LINE__, __hook_registed) = false; \
    if(!_S3(__, __LINE__, __hook_registed))  \
        hookManager.AddHooker(&_S3(__, __LINE__, __hook_registed), __PRETTY_FUNCTION__, STRINGIZE(__LINE__)); \
    hookManager.Trigger(&_S3(__, __LINE__, __hook_registed), __VA_ARGS__);

#endif
