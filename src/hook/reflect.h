#ifndef HOOK_REFLECT_H__
#define HOOK_REFLECT_H__

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// ============================================================================
// reflect macros
// ============================================================================

#define reflect_field(x) v(#x, x);
#define reflect_const_field(x) v(#x, static_cast<const decltype(x)&>(x));
#define reflect_named(name, x) v(name, x);
#define reflect_const(name, x) v(name, static_cast<const decltype(x)&>(x));

#define REFLECT_ALL_1(v, a1) reflect_field(a1)
#define REFLECT_ALL_2(v, a1, a2) reflect_field(a1) reflect_field(a2)
#define REFLECT_ALL_3(v, a1, a2, a3) reflect_field(a1) reflect_field(a2) reflect_field(a3)
#define REFLECT_ALL_4(v, a1, a2, a3, a4) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4)
#define REFLECT_ALL_5(v, a1, a2, a3, a4, a5) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5)
#define REFLECT_ALL_6(v, a1, a2, a3, a4, a5, a6) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6)
#define REFLECT_ALL_7(v, a1, a2, a3, a4, a5, a6, a7) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7)
#define REFLECT_ALL_8(v, a1, a2, a3, a4, a5, a6, a7, a8) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8)
#define REFLECT_ALL_9(v, a1, a2, a3, a4, a5, a6, a7, a8, a9) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9)
#define REFLECT_ALL_10(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10)
#define REFLECT_ALL_11(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10) reflect_field(a11)
#define REFLECT_ALL_12(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10) reflect_field(a11) reflect_field(a12)
#define REFLECT_ALL_GET(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,NAME,...) NAME
#define reflect_all(...) REFLECT_ALL_GET(__VA_ARGS__, REFLECT_ALL_12, REFLECT_ALL_11, REFLECT_ALL_10, REFLECT_ALL_9, REFLECT_ALL_8, REFLECT_ALL_7, REFLECT_ALL_6, REFLECT_ALL_5, REFLECT_ALL_4, REFLECT_ALL_3, REFLECT_ALL_2, REFLECT_ALL_1)(v, __VA_ARGS__)

// ============================================================================
// type traits
// ============================================================================

template<typename T, typename = void>
struct has_reflect : std::false_type {};

template<typename...>
struct dependent_false : std::false_type {};

template<typename T, typename = void>
struct is_complete : std::false_type {};

template<typename T>
struct is_complete<T, std::void_t<decltype(sizeof(T))>> : std::true_type {};

template<typename T, bool = is_complete<T>::value>
struct is_blob_aggregate_impl : std::false_type {};

template<typename T>
struct is_blob_aggregate_impl<T, true>
    : std::bool_constant<!std::is_array_v<T> && std::is_aggregate_v<T> && std::is_trivially_copyable_v<T>> {};

template<typename T>
struct is_blob_aggregate : is_blob_aggregate_impl<T> {};

// Forward declaration for has_member_reflect detection
class IVisitor;

template<typename T, typename = void>
struct has_member_reflect : std::false_type {};

template<typename T>
struct has_member_reflect<T, std::void_t<decltype(std::declval<T&>().reflect(std::declval<IVisitor&>()))>> : std::true_type {};

template<typename T>
struct has_reflect<T, std::enable_if_t<has_member_reflect<T>::value>> : std::true_type {};
template<typename T, typename = void>
struct is_smart_pointer : std::false_type {};

template<typename T>
struct is_smart_pointer<T, std::void_t<typename T::element_type,
    decltype(std::declval<T>().get())>> : std::true_type {};

template<typename T>
struct is_vector : std::false_type {};

template<typename T, typename A>
struct is_vector<std::vector<T, A>> : std::true_type {};

template<typename T>
struct is_deque : std::false_type {};

template<typename T, typename A>
struct is_deque<std::deque<T, A>> : std::true_type {};

template<typename T>
struct is_list : std::false_type {};

template<typename T, typename A>
struct is_list<std::list<T, A>> : std::true_type {};

template<typename T>
struct is_set : std::false_type {};

template<typename K, typename C, typename A>
struct is_set<std::set<K, C, A>> : std::true_type {};

template<typename T>
struct is_map : std::false_type {};

template<typename K, typename V, typename C, typename A>
struct is_map<std::map<K, V, C, A>> : std::true_type {};

template<typename T>
struct is_span : std::false_type {};

template<typename T, std::size_t E>
struct is_span<std::span<T, E>> : std::true_type {};

template<typename T>
struct is_byte_span : std::false_type {};

template<typename T, std::size_t E>
struct is_byte_span<std::span<T, E>>
    : std::bool_constant<std::is_same_v<std::remove_cv_t<T>, std::byte>> {};

// IVisitor - virtual visitor base for the reflection system.
//
// reflect(IVisitor&) is virtual, enabling correct dispatch through
// base class pointers.  The template operator() does compile-time
// type dispatch and calls virtual leaf/scope methods that concrete
// visitors (SerializeVisitor, SetFieldVisitor) override.
//
// Read-only detection: operator() checks is_const and is_lvalue_reference
// on the deduced T&& to decide between mutable leaf_*() and read-only
// leaf_ro_*() calls.

class IVisitor {
public:
    virtual ~IVisitor() = default;

    // --- Mode ---
    enum class Mode { Serialize, SetField };
    virtual Mode mode() const = 0;

    // --- Scope management ---
    virtual void push(const char* name) = 0;
    virtual void pop() = 0;
    virtual void push_map_key(const std::string& key) = 0;
    virtual void pop_map_key() = 0;

    // --- Mutable leaf handlers (writable fields) ---
    virtual void leaf_i64(const char* name, int64_t& val) = 0;
    virtual void leaf_u64(const char* name, uint64_t& val) = 0;
    virtual void leaf_str(const char* name, std::string& val) = 0;
    virtual void leaf_cstr(const char* name, char* val, size_t maxlen) = 0;
    virtual void leaf_blob(const char* name, void* data, size_t len) = 0;

    // --- Read-only leaf handlers (const fields / temporaries) ---
    virtual void leaf_ro_i64(const char* name, int64_t val) = 0;
    virtual void leaf_ro_u64(const char* name, uint64_t val) = 0;
    virtual void leaf_ro_str(const char* name, const std::string& val) = 0;
    virtual void leaf_ro_blob(const char* name, const void* data, size_t len) = 0;

    // --- SetField helpers (default no-ops for SerializeVisitor) ---
    virtual const std::string& target_key() const { static std::string e; return e; }
    virtual std::string current_path() const { return {}; }
    virtual int& result_ref() { static int d = 0; return d; }

    // --- Template operator() -- compile-time type dispatch ---
    template<typename T>
    void operator()(const char* name, T&& val);

private:
    // Scalar dispatch helpers
    template<typename T> void dispatch_bool(const char* name, T&& val);
    template<typename T> void dispatch_enum(const char* name, T&& val);
    template<typename T> void dispatch_string(const char* name, T&& val);
    template<typename T> void dispatch_char_array(const char* name, T&& val);
    template<typename T> void dispatch_byte_span(const char* name, T&& val);
    template<typename T> void dispatch_blob(const char* name, T&& val);
    template<typename T> void dispatch_float(const char* name, T&& val);
    template<typename T> void dispatch_integral(const char* name, T&& val);
    // Container dispatch helpers
    template<typename T> void dispatch_map(const char* name, T&& val);
    template<typename T> void dispatch_sequence(const char* name, T&& val);
    template<typename T> void dispatch_set(const char* name, T&& val);
    // Indirection dispatch helpers
    template<typename T> void dispatch_deref(const char* name, T&& val);
    template<typename T> void dispatch_reflectable(const char* name, T&& val);
};

// ============================================================================
// map_key_to_string - converts map keys to string for IVisitor
// ============================================================================

template<typename T>
std::string map_key_to_string(const T& key) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_same_v<Raw, std::string>) {
        return key;
    } else if constexpr (std::is_same_v<Raw, const char*> || std::is_same_v<Raw, char*>) {
        return key ? std::string(key) : std::string();
    } else if constexpr (std::is_enum_v<Raw>) {
        using Underlying = std::underlying_type_t<Raw>;
        return map_key_to_string(static_cast<Underlying>(key));
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        return std::to_string(static_cast<unsigned long long>(key));
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        return std::to_string(static_cast<long long>(key));
    } else {
        static_assert(dependent_false<Raw>::value,
            "Unsupported map key type in map_key_to_string");
    }
}

// ============================================================================
// HookReflectable - virtual base for hook reflect dispatch.
// ============================================================================

// Root classes (Server, Http2Base, Http3Base, HttpBase, Ep, Ip) use
// virtual inheritance to avoid diamond ambiguity in multiply-derived
// leaf classes (Guest2, Proxy2, etc.).
//
// reflect(IVisitor&) is the single virtual entry point for both
// serialization and write-back.  Concrete visitors determine behavior.

class HookReflectable {
public:
    virtual void reflect(IVisitor& v) = 0;
    virtual ~HookReflectable() = default;
};

// ============================================================================
// Scalar dispatch helpers
// ============================================================================

template<typename T>
void IVisitor::dispatch_bool(const char* name, T&& val) {
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (!is_const && is_lval) {
        uint64_t tmp = val ? 1u : 0u;
        leaf_u64(name, tmp);
        val = tmp != 0;
    } else {
        leaf_ro_u64(name, val ? 1u : 0u);
    }
}

template<typename T>
void IVisitor::dispatch_enum(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    using U = std::underlying_type_t<Raw>;
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (std::is_signed_v<U>) {
        if constexpr (!is_const && is_lval) {
            int64_t tmp = static_cast<int64_t>(static_cast<U>(val));
            leaf_i64(name, tmp);
            val = static_cast<Raw>(static_cast<U>(tmp));
        } else {
            leaf_ro_i64(name, static_cast<int64_t>(static_cast<U>(val)));
        }
    } else {
        if constexpr (!is_const && is_lval) {
            uint64_t tmp = static_cast<uint64_t>(static_cast<U>(val));
            leaf_u64(name, tmp);
            val = static_cast<Raw>(static_cast<U>(tmp));
        } else {
            leaf_ro_u64(name, static_cast<uint64_t>(static_cast<U>(val)));
        }
    }
}

template<typename T>
void IVisitor::dispatch_string(const char* name, T&& val) {
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (!is_const && is_lval) leaf_str(name, val);
    else leaf_ro_str(name, val);
}

template<typename T>
void IVisitor::dispatch_char_array(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    if constexpr (!is_const) leaf_cstr(name, val, std::extent_v<Raw>);
    else leaf_ro_blob(name, val, strnlen(val, std::extent_v<Raw>));
}

template<typename T>
void IVisitor::dispatch_byte_span(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (std::is_const_v<typename Raw::element_type> || is_const || !is_lval)
        leaf_ro_blob(name, val.data(), val.size_bytes());
    else
        leaf_blob(name, val.data(), val.size_bytes());
}

template<typename T>
void IVisitor::dispatch_blob(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (!is_const && is_lval) leaf_blob(name, &val, sizeof(Raw));
    else leaf_ro_blob(name, &val, sizeof(Raw));
}

template<typename T>
void IVisitor::dispatch_float(const char* name, T&& val) {
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (!is_const && is_lval) {
        uint64_t tmp;
        memcpy(&tmp, &val, sizeof(double));
        leaf_u64(name, tmp);
        memcpy(&val, &tmp, sizeof(double));
    } else {
        uint64_t tmp;
        memcpy(&tmp, &val, sizeof(double));
        leaf_ro_u64(name, tmp);
    }
}

template<typename T>
void IVisitor::dispatch_integral(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    constexpr bool is_const = std::is_const_v<std::remove_reference_t<T>>;
    constexpr bool is_lval  = std::is_lvalue_reference_v<T&&>;
    if constexpr (std::is_signed_v<Raw>) {
        if constexpr (!is_const && is_lval) {
            int64_t tmp = static_cast<int64_t>(val);
            leaf_i64(name, tmp);
            val = static_cast<Raw>(tmp);
        } else {
            leaf_ro_i64(name, static_cast<int64_t>(val));
        }
    } else {
        if constexpr (!is_const && is_lval) {
            uint64_t tmp = static_cast<uint64_t>(val);
            leaf_u64(name, tmp);
            val = static_cast<Raw>(tmp);
        } else {
            leaf_ro_u64(name, static_cast<uint64_t>(val));
        }
    }
}

// ============================================================================
// Container dispatch helpers
// ============================================================================

template<typename T>
void IVisitor::dispatch_map(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    push(name);
    if (mode() == Mode::Serialize) {
        for (auto& [k, v] : val) {
            std::string ks = map_key_to_string(k);
            push_map_key(ks);
            (*this)(nullptr, v);
            pop_map_key();
        }
    } else {
        // SetField: parse [key] from target, do targeted lookup
        const std::string& tgt = target_key();
        std::string full = current_path();
        if (full == tgt.substr(0, full.size())) {
            size_t bracket = tgt.find('[', full.size());
            if (bracket != std::string::npos && bracket == full.size()) {
                auto bracket_end = tgt.find(']', bracket + 1);
                if (bracket_end != std::string::npos) {
                    std::string key_str = tgt.substr(bracket + 1, bracket_end - bracket - 1);
                    push_map_key(key_str);
                    using Key = typename Raw::key_type;
                    Key map_key{};
                    if constexpr (std::is_same_v<Key, std::string>) {
                        map_key = key_str;
                    } else if constexpr (std::is_unsigned_v<Key> && std::is_integral_v<Key>) {
                        map_key = static_cast<Key>(strtoull(key_str.c_str(), nullptr, 10));
                    } else if constexpr (std::is_signed_v<Key> && std::is_integral_v<Key>) {
                        map_key = static_cast<Key>(strtoll(key_str.c_str(), nullptr, 10));
                    }
                    auto it = val.find(map_key);
                    if (it != val.end()) {
                        (*this)(nullptr, it->second);
                    } else if constexpr (std::is_default_constructible_v<typename Raw::mapped_type>) {
                        if (bracket_end + 1 >= tgt.size()) {
                            auto [new_it, inserted] = val.try_emplace(map_key);
                            (*this)(nullptr, new_it->second);
                            if (inserted && result_ref() != 0) {
                                val.erase(new_it);
                            }
                        }
                    }
                    pop_map_key();
                }
            }
        }
    }
    pop();
}

template<typename T>
void IVisitor::dispatch_sequence(const char* name, T&& val) {
    push(name);
    if (mode() == Mode::Serialize) {
        size_t idx = 0;
        for (auto& item : val) {
            std::string ks = std::to_string(idx++);
            push_map_key(ks);
            (*this)(nullptr, item);
            pop_map_key();
        }
    } else {
        // SetField: parse [idx] from target, do targeted access
        const std::string& tgt = target_key();
        std::string full = current_path();
        if (full == tgt.substr(0, full.size())) {
            size_t bracket = tgt.find('[', full.size());
            if (bracket != std::string::npos && bracket == full.size()) {
                auto bracket_end = tgt.find(']', bracket + 1);
                if (bracket_end != std::string::npos) {
                    std::string idx_str = tgt.substr(bracket + 1, bracket_end - bracket - 1);
                    char* endptr = nullptr;
                    size_t idx = strtoull(idx_str.c_str(), &endptr, 10);
                    if (endptr != idx_str.c_str() && *endptr == '\0') {
                        push_map_key(idx_str);
                        if (idx < val.size()) {
                            auto it = val.begin();
                            std::advance(it, idx);
                            (*this)(nullptr, *it);
                        } else {
                            result_ref() = -EINVAL;
                        }
                        pop_map_key();
                    }
                }
            }
        }
    }
    pop();
}

template<typename T>
void IVisitor::dispatch_set(const char* name, T&& val) {
    push(name);
    if (mode() == Mode::Serialize) {
        size_t idx = 0;
        for (auto& item : val) {
            std::string ks = std::to_string(idx++);
            push_map_key(ks);
            (*this)(nullptr, item);
            pop_map_key();
        }
    } else {
        const std::string& tgt = target_key();
        std::string full = current_path();
        if (tgt.size() > full.size() && tgt.compare(0, full.size(), full) == 0
            && tgt[full.size()] == '[') {
            result_ref() = -EACCES;
        }
    }
    pop();
}

// ============================================================================
// Indirection dispatch helpers
// ============================================================================

template<typename T>
void IVisitor::dispatch_deref(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (is_smart_pointer<Raw>::value) {
        using Elem = typename Raw::element_type;
        if constexpr (is_complete<Elem>::value) {
            if (val) (*this)(name, *val);
        }
    } else {
        using Elem = std::remove_pointer_t<Raw>;
        if constexpr (is_complete<Elem>::value) {
            if (val) (*this)(name, *val);
        }
    }
}

template<typename T>
void IVisitor::dispatch_reflectable(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    push(name);
    const_cast<Raw&>(val).reflect(*this);
    pop();
}

// ============================================================================
// operator() - main type dispatcher
// ============================================================================

template<typename T>
void IVisitor::operator()(const char* name, T&& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;

    // Scalars
    if constexpr (std::is_same_v<Raw, bool>)
        dispatch_bool(name, std::forward<T>(val));
    else if constexpr (std::is_enum_v<Raw>)
        dispatch_enum(name, std::forward<T>(val));
    else if constexpr (std::is_same_v<Raw, std::string>)
        dispatch_string(name, std::forward<T>(val));
    else if constexpr (std::is_array_v<Raw> && std::is_same_v<std::remove_extent_t<Raw>, char>)
        dispatch_char_array(name, std::forward<T>(val));
    else if constexpr (is_byte_span<Raw>::value)
        dispatch_byte_span(name, std::forward<T>(val));
    else if constexpr (is_blob_aggregate<Raw>::value)
        dispatch_blob(name, std::forward<T>(val));
    else if constexpr (std::is_floating_point_v<Raw>)
        dispatch_float(name, std::forward<T>(val));
    else if constexpr (std::is_integral_v<Raw>)
        dispatch_integral(name, std::forward<T>(val));
    // Containers
    else if constexpr (is_map<Raw>::value)
        dispatch_map(name, std::forward<T>(val));
    else if constexpr (is_vector<Raw>::value || is_deque<Raw>::value
                       || is_list<Raw>::value || is_span<Raw>::value)
        dispatch_sequence(name, std::forward<T>(val));
    else if constexpr (is_set<Raw>::value)
        dispatch_set(name, std::forward<T>(val));
    // Indirection
    else if constexpr (is_smart_pointer<Raw>::value
                       || (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>))
        dispatch_deref(name, std::forward<T>(val));
    // Reflectable objects
    else if constexpr (is_complete<Raw>::value
                       && (std::is_base_of_v<HookReflectable, Raw> || has_reflect<Raw>::value))
        dispatch_reflectable(name, std::forward<T>(val));
    else
        static_assert(dependent_false<Raw>::value, "Unsupported type in reflect");
}

#endif // HOOK_REFLECT_H__
