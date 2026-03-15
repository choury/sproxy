#ifndef HOOK_H__
#define HOOK_H__
#include "common/common.h"
#include "hook_callback.h"

#include <memory>
#include <tuple>
#include <unordered_map>
#include <string>
#include <vector>
#include <dlfcn.h>
#include <stdarg.h>

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
    void Trigger(const void* hooker, Args&&... args);

#ifdef HAVE_BPFVM
    template <typename... Args>
    void TriggerBpf(const void* hooker, Args&&... args);
#endif

    bool AddHooker(bool* hooker, std::string func, const char* line, const char* names);

    const std::unordered_map<const void*, std::string>& GetHookers() const {
        return hookers;
    }

    // Get parameter names for a hook point (set by AddHooker with names)
    const std::vector<std::string>& GetParamNames(const void* hooker) const {
        static const std::vector<std::string> empty;
        auto it = param_names_map.find(hooker);
        if (it != param_names_map.end()) return it->second;
        return empty;
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
    std::unordered_map<const void*, std::vector<std::string>> param_names_map;
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

#define HOOK_FUNC(...) \
    static bool  _S3(__, __LINE__, __hook_registed) = false; \
    if(!_S3(__, __LINE__, __hook_registed))  \
        hookManager.AddHooker(&_S3(__, __LINE__, __hook_registed), __PRETTY_FUNCTION__, STRINGIZE(__LINE__), #__VA_ARGS__); \
    hookManager.Trigger(&_S3(__, __LINE__, __hook_registed), __VA_ARGS__);

#ifdef HAVE_BPFVM
#define HOOK_BPF(...) \
    static bool  _S3(__, __LINE__, __hook_registed) = false; \
    if(!_S3(__, __LINE__, __hook_registed))  \
        hookManager.AddHooker(&_S3(__, __LINE__, __hook_registed), __PRETTY_FUNCTION__, STRINGIZE(__LINE__), #__VA_ARGS__); \
    hookManager.TriggerBpf(&_S3(__, __LINE__, __hook_registed), __VA_ARGS__);

// Include BpfCallback definition needed by Trigger template below
#include "bpf_bridge.h"
#endif

// Trigger template: dispatches to LibCallback (OnCall)
template <typename... Args>
void HookManager::Trigger(const void* hooker, Args&&... args) {
    auto it = callbacks.find(hooker);
    if(it == callbacks.end()) {
        return;
    }
    auto t = std::tie(args...);
    it->second->OnCall(&t);
}

#ifdef HAVE_BPFVM
// TriggerBpf template: serializes args, constructs kv_set callback, passes to OnCall
template <typename... Args>
void HookManager::TriggerBpf(const void* hooker, Args&&... args) {
    using namespace bpf_detail;
    static_assert((is_bpf_serializable<std::remove_reference_t<Args>>::value && ...),
        "HOOK_BPF: all parameters must be BPF-serializable (integral, string, or have a reflect method)");
    auto it = callbacks.find(hooker);
    if(it == callbacks.end()) {
        return;
    }
    const auto& param_names = GetParamNames(hooker);
    auto t = std::tie(args...);

    // Serialize parameters to protobuf (needs type info)
    BpfCallArgs bpf_args;
    serialize_tuple(bpf_args.pb_data, param_names, t,
                    std::index_sequence_for<Args...>{});

    // Construct write-back callback (needs type info)
    bpf_args.kv_set = [&param_names, &t](const std::string& key, const BpfKV& kv) {
        set_tuple_field(param_names, key, kv, t,
                        std::index_sequence_for<Args...>{});
    };

    it->second->OnCall(&bpf_args);
}
#endif

#endif
