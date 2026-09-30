#ifndef HOOK_H__
#define HOOK_H__
#include "common/common.h"
#include "hook_callback.h"
#include "bpf_bridge.h"

#include <memory>
#include <tuple>
#include <unordered_map>
#include <string>
#include <vector>

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

    template <bpf_detail::Names N, typename... Args>
    void Trigger(const void* hooker, Args&&... args);

    bool AddHooker(bool* hooker, std::string func, const char* line);

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

    void AddHookSymbol(const void* addr, const char* mangled);
};

extern HookManager hookManager;

#define __S3(a, b, c) a##b##c
#define _S3(a, b, c) __S3(a, b, c)

#define _HOOK_NAME_1(a1) #a1
#define _HOOK_NAME_2(a1, a2) #a1, #a2
#define _HOOK_NAME_3(a1, a2, a3) #a1, #a2, #a3
#define _HOOK_NAME_4(a1, a2, a3, a4) #a1, #a2, #a3, #a4
#define _HOOK_NAME_5(a1, a2, a3, a4, a5) #a1, #a2, #a3, #a4, #a5
#define _HOOK_NAME_6(a1, a2, a3, a4, a5, a6) #a1, #a2, #a3, #a4, #a5, #a6
#define _HOOK_NAME_7(a1, a2, a3, a4, a5, a6, a7) #a1, #a2, #a3, #a4, #a5, #a6, #a7
#define _HOOK_NAME_8(a1, a2, a3, a4, a5, a6, a7, a8) #a1, #a2, #a3, #a4, #a5, #a6, #a7, #a8
#define _HOOK_NAME_9(a1, a2, a3, a4, a5, a6, a7, a8, a9) #a1, #a2, #a3, #a4, #a5, #a6, #a7, #a8, #a9
#define _HOOK_NAME_10(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) #a1, #a2, #a3, #a4, #a5, #a6, #a7, #a8, #a9, #a10
#define _HOOK_NAME_11(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) #a1, #a2, #a3, #a4, #a5, #a6, #a7, #a8, #a9, #a10, #a11
#define _HOOK_NAME_12(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) #a1, #a2, #a3, #a4, #a5, #a6, #a7, #a8, #a9, #a10, #a11, #a12
#define _HOOK_NAME_GET(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, NAME, ...) NAME
#define _HOOK_NAME_LIST(...) _HOOK_NAME_GET(__VA_ARGS__, _HOOK_NAME_12, _HOOK_NAME_11, _HOOK_NAME_10, _HOOK_NAME_9, _HOOK_NAME_8, _HOOK_NAME_7, _HOOK_NAME_6, _HOOK_NAME_5, _HOOK_NAME_4, _HOOK_NAME_3, _HOOK_NAME_2, _HOOK_NAME_1)(__VA_ARGS__)

#define _HOOK_NARG(...) _HOOK_NAME_GET(__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define HOOK_BPF(...) \
    static bool  _S3(__, __LINE__, __hook_registed) = false; \
    static constexpr bpf_detail::Names<_HOOK_NARG(__VA_ARGS__)> _S3(__, __LINE__, __hook_names){_HOOK_NAME_LIST(__VA_ARGS__)}; \
    if(!_S3(__, __LINE__, __hook_registed))  \
        hookManager.AddHooker(&_S3(__, __LINE__, __hook_registed), __PRETTY_FUNCTION__, STRINGIZE(__LINE__)); \
    hookManager.Trigger<_S3(__, __LINE__, __hook_names)>(&_S3(__, __LINE__, __hook_registed), __VA_ARGS__);


// Trigger template: BPF-aware dispatch path when HAVE_ELF is enabled.
template <bpf_detail::Names N, typename... Args>
void HookManager::Trigger(const void* hooker, Args&&... args) {
#ifdef HAVE_ELF
    using namespace bpf_detail;
    static_assert((is_bpf_serializable<std::remove_cv_t<std::remove_reference_t<Args>>>::value && ...),
        "HOOK_BPF: all parameters must be BPF-serializable (integral, string, or have a reflect method)");
    static_assert(!N.has_prefix_conflict(),
        "HOOK_BPF: one parameter name is a prefix of another (e.g. obj and obj->field); "
        "the nested entry would be shadowed by the first-match decoder on the wire");
    auto it = callbacks.find(hooker);
    if(it == callbacks.end()) {
        return;
    }
    auto t = std::tie(args...);

    // Serialize parameters to protobuf (needs type info)
    BpfCallArgs bpf_args;
    serialize_tuple(bpf_args.pb_data, N, t,
                    typename Permuted<N, std::index_sequence_for<Args...>>::type{});

    // Construct write-back callback (needs type info)
    bpf_args.kv_set = [&t](const std::string& key, const BpfKV& kv) -> int {
        return set_tuple_field(N, key, kv, t, std::index_sequence_for<Args...>{});
    };

    it->second->OnCall(&bpf_args);
#else
    (void)hooker;
    (void)sizeof...(args);
#endif
}

#endif
