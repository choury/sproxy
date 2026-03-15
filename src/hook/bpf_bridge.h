#ifndef BPF_BRIDGE_H__
#define BPF_BRIDGE_H__

#include "hook_callback.h"
#include "bpfvm/insn.h"

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <unordered_map>
#include <type_traits>
#include <tuple>
#include <cstring>

// KV value types for BPF syscall write-back
struct BpfKV {
    enum Type { NONE, INT64, UINT64, STRING, BYTES };
    Type type = NONE;
    union {
        int64_t  i64;
        uint64_t u64;
    };
    std::string str;

    BpfKV() : i64(0) {}
    static BpfKV make_int(int64_t v) { BpfKV kv; kv.type = INT64; kv.i64 = v; return kv; }
    static BpfKV make_uint(uint64_t v) { BpfKV kv; kv.type = UINT64; kv.u64 = v; return kv; }
    static BpfKV make_string(const std::string& v) { BpfKV kv; kv.type = STRING; kv.str = v; return kv; }
    static BpfKV make_bytes(const void* data, size_t len) {
        BpfKV kv; kv.type = BYTES; kv.str.assign((const char*)data, len); return kv;
    }
};

namespace bpf_detail {

// ============ Protobuf wire format encoding ============
//
// KVMap   { repeated MapEntry entries = 1; }
// MapEntry { string key = 1; Value value = 2; }
// Value   { int64 = 1; uint64 = 2; string = 3; bytes = 4; KVMap = 5; Array = 6; }
// Array   { repeated Value elements = 1; }

inline void pb_append_varint(std::string& out, uint64_t val) {
    while (val > 0x7F) {
        out.push_back((char)((val & 0x7F) | 0x80));
        val >>= 7;
    }
    out.push_back((char)(val & 0x7F));
}

inline void pb_append_tag(std::string& out, uint32_t field, uint32_t wire_type) {
    pb_append_varint(out, ((uint64_t)field << 3) | wire_type);
}

inline void pb_append_bytes_field(std::string& out, uint32_t field, const void* data, size_t len) {
    pb_append_tag(out, field, 2);
    pb_append_varint(out, len);
    out.append((const char*)data, len);
}

inline void pb_append_varint_field(std::string& out, uint32_t field, uint64_t val) {
    pb_append_tag(out, field, 0);
    pb_append_varint(out, val);
}

// Append a MapEntry { key = 1, value = 2 } as KVMap field 1
inline void pb_append_map_entry(std::string& kvmap, const std::string& key,
                                const std::string& value_msg) {
    std::string entry;
    pb_append_bytes_field(entry, 1, key.data(), key.size());
    pb_append_bytes_field(entry, 2, value_msg.data(), value_msg.size());
    pb_append_bytes_field(kvmap, 1, entry.data(), entry.size());
}

// ============ Type traits ============

template<typename T, typename = void>
struct has_reflect : std::false_type {};
template<typename T>
struct has_reflect<T, std::void_t<decltype(std::declval<const T>().reflect(std::declval<int&>()))>> : std::true_type {};

template<typename T, typename = void>
struct is_smart_pointer : std::false_type {};
template<typename T>
struct is_smart_pointer<T, std::void_t<typename T::element_type,
    decltype(std::declval<T>().get())>> : std::true_type {};

template<typename T> struct is_vector : std::false_type {};
template<typename T, typename A> struct is_vector<std::vector<T, A>> : std::true_type {};

template<typename T> struct is_string_map : std::false_type {};
template<typename V, typename C, typename A>
struct is_string_map<std::map<std::string, V, C, A>> : std::true_type {};

// ============ Serialize: reflect → nested protobuf ============

// serialize_value: produce a Value message for a single value
template<typename T>
std::string serialize_value(const T& val);

// Visitor that builds a KVMap from reflected fields
struct SerializeVisitor {
    std::string& kvmap; // accumulates KVMap entries
    template<typename T>
    void operator()(const char* name, const T& val) {
        std::string val_msg = serialize_value(val);
        pb_append_map_entry(kvmap, name, val_msg);
    }
};

template<typename T>
std::string serialize_value(const T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    std::string value_msg;
    if constexpr (std::is_same_v<Raw, std::string>) {
        pb_append_bytes_field(value_msg, 3, val.data(), val.size());
    } else if constexpr (std::is_same_v<Raw, const char*> || std::is_same_v<Raw, char*>) {
        const char* s = val ? val : "";
        pb_append_bytes_field(value_msg, 3, s, strlen(s));
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        pb_append_varint_field(value_msg, 1, (uint64_t)(int64_t)val);
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        pb_append_varint_field(value_msg, 2, (uint64_t)val);
    } else if constexpr (is_vector<Raw>::value) {
        // Value field 6 = Array { repeated Value elements = 1 }
        std::string array_msg;
        for (size_t i = 0; i < val.size(); ++i) {
            std::string elem = serialize_value(val[i]);
            pb_append_bytes_field(array_msg, 1, elem.data(), elem.size());
        }
        pb_append_bytes_field(value_msg, 6, array_msg.data(), array_msg.size());
    } else if constexpr (is_string_map<Raw>::value) {
        // Value field 5 = KVMap
        std::string kvmap;
        for (const auto& [k, v] : val) {
            std::string v_msg = serialize_value(v);
            pb_append_map_entry(kvmap, k, v_msg);
        }
        pb_append_bytes_field(value_msg, 5, kvmap.data(), kvmap.size());
    } else if constexpr (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>) {
        if (val) return serialize_value(*val);
    } else if constexpr (is_smart_pointer<Raw>::value) {
        if (val) return serialize_value(*val);
    } else if constexpr (has_reflect<Raw>::value) {
        // Value field 5 = KVMap (nested object)
        std::string kvmap;
        SerializeVisitor v{kvmap};
        val.reflect(v);
        pb_append_bytes_field(value_msg, 5, kvmap.data(), kvmap.size());
    }
    return value_msg;
}

// Top-level: serialize tuple to a KVMap
template<typename Tuple, size_t... Is>
void serialize_tuple(std::string& out, const std::vector<std::string>& names,
                     const Tuple& t, std::index_sequence<Is...>) {
    struct PBNode {
        std::string val_msg;
        std::map<std::string, PBNode> children;
        void insert(const std::string& path, const std::string& vmsg) {
            size_t dot = path.find('.');
            if (dot == std::string::npos) {
                children[path].val_msg = vmsg;
            } else {
                children[path.substr(0, dot)].insert(path.substr(dot + 1), vmsg);
            }
        }
        std::string serialize() const {
            if (!val_msg.empty()) return val_msg;
            std::string kvmap;
            for (const auto& kv : children) {
                pb_append_map_entry(kvmap, kv.first, kv.second.serialize());
            }
            std::string value_msg;
            pb_append_bytes_field(value_msg, 5, kvmap.data(), kvmap.size());
            return value_msg;
        }
    };
    PBNode root;
    ((root.insert(Is < names.size() ? names[Is] : "arg" + std::to_string(Is),
                  serialize_value(std::get<Is>(t)))), ...);

    for (const auto& kv : root.children) {
        pb_append_map_entry(out, kv.first, kv.second.serialize());
    }
}

// ============ Write-back: kv_set → reflect directly ============

template<typename T>
bool set_param(const std::string& name, const std::string& key, const BpfKV& kv, T& val);

struct SetFieldVisitor {
    const std::string& prefix;
    const std::string& key;
    const BpfKV& kv;
    bool found = false;
    template<typename T>
    void operator()(const char* name, const T& val) {
        if (found) return;
        std::string full = prefix.empty() ? std::string(name) : prefix + "." + name;
        found = set_param(full, key, kv, const_cast<T&>(val));
    }
};

template<typename T>
bool set_param(const std::string& name, const std::string& key, const BpfKV& kv, T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_const_v<T>) {
        return false;
    } else if constexpr (std::is_same_v<Raw, std::string>) {
        if (name == key && (kv.type == BpfKV::STRING || kv.type == BpfKV::BYTES)) {
            val = kv.str;
            return true;
        }
        return false;
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        if (name == key && (kv.type == BpfKV::INT64 || kv.type == BpfKV::UINT64)) {
            val = static_cast<T>(kv.type == BpfKV::INT64 ? kv.i64 : (int64_t)kv.u64);
            return true;
        }
        return false;
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        if (name == key && (kv.type == BpfKV::UINT64 || kv.type == BpfKV::INT64)) {
            val = static_cast<T>(kv.type == BpfKV::UINT64 ? kv.u64 : (uint64_t)kv.i64);
            return true;
        }
        return false;
    } else if constexpr (is_vector<Raw>::value) {
        // key must start with name[idx]...
        if (key.size() <= name.size() || key.compare(0, name.size(), name) != 0
            || key[name.size()] != '[') {
            return false;
        }
        auto bracket_end = key.find(']', name.size() + 1);
        if (bracket_end == std::string::npos) return false;
        std::string idx_str = key.substr(name.size() + 1, bracket_end - name.size() - 1);
        char* endptr = nullptr;
        size_t idx = strtoull(idx_str.c_str(), &endptr, 10);
        if (endptr == idx_str.c_str() || *endptr != '\0') return false;
        if (idx >= val.size()) return false;
        // rest after ']'
        std::string rest_key = key.substr(bracket_end + 1);
        if (rest_key.empty()) {
            // direct assignment to element
            return set_param(name + "[" + std::to_string(idx) + "]", key, kv, val[idx]);
        }
        // strip leading '.' for nested access
        if (rest_key[0] == '.') rest_key = rest_key.substr(1);
        std::string elem_name = name + "[" + std::to_string(idx) + "]";
        return set_param(elem_name, elem_name + "." + rest_key, kv, val[idx]);
    } else if constexpr (is_string_map<Raw>::value) {
        // key must start with name[map_key]...
        if (key.size() <= name.size() || key.compare(0, name.size(), name) != 0
            || key[name.size()] != '[') {
            return false;
        }
        auto bracket_end = key.find(']', name.size() + 1);
        if (bracket_end == std::string::npos) return false;
        std::string map_key = key.substr(name.size() + 1, bracket_end - name.size() - 1);
        // rest after ']'
        std::string rest_key = key.substr(bracket_end + 1);
        std::string elem_name = name + "[" + map_key + "]";
        if (rest_key.empty()) {
            // Use operator[] to auto-create entry
            return set_param(elem_name, key, kv, val[map_key]);
        }
        if (rest_key[0] == '.') rest_key = rest_key.substr(1);
        return set_param(elem_name, elem_name + "." + rest_key, kv, val[map_key]);
    } else if constexpr (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>) {
        if (val) return set_param(name, key, kv, *val);
        return false;
    } else if constexpr (is_smart_pointer<Raw>::value) {
        if (val) return set_param(name, key, kv, *val);
        return false;
    } else if constexpr (has_reflect<Raw>::value) {
        SetFieldVisitor v{name, key, kv};
        const_cast<Raw&>(val).reflect(v);
        return v.found;
    }
    return false;
}

template<typename Tuple, size_t... Is>
bool set_tuple_field(const std::vector<std::string>& names, const std::string& key,
                     const BpfKV& kv, Tuple& t, std::index_sequence<Is...>) {
    return (set_param(Is < names.size() ? names[Is] : "arg" + std::to_string(Is),
                      key, kv, std::get<Is>(t)) || ...);
}

// ============ Compile-time serializability check ============

template<typename T, typename = void>
struct is_bpf_serializable : std::false_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<std::is_integral_v<std::remove_cv_t<std::remove_reference_t<T>>>>> : std::true_type {};
template<> struct is_bpf_serializable<std::string> : std::true_type {};
template<> struct is_bpf_serializable<const char*> : std::true_type {};
template<> struct is_bpf_serializable<char*> : std::true_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<
    has_reflect<std::remove_cv_t<std::remove_reference_t<T>>>::value
    && !std::is_integral_v<std::remove_cv_t<std::remove_reference_t<T>>>
>> : std::true_type {};

template<typename T>
struct is_bpf_serializable<T*, std::enable_if_t<
    !std::is_void_v<T> && is_bpf_serializable<T>::value
>> : std::true_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<
    is_smart_pointer<std::remove_cv_t<std::remove_reference_t<T>>>::value
    && is_bpf_serializable<typename std::remove_cv_t<std::remove_reference_t<T>>::element_type>::value
>> : std::true_type {};

// vector of serializable element types
template<typename T, typename A>
struct is_bpf_serializable<std::vector<T, A>, std::enable_if_t<
    is_bpf_serializable<T>::value
>> : std::true_type {};

// map<string, V> where V is serializable
template<typename V, typename C, typename A>
struct is_bpf_serializable<std::map<std::string, V, C, A>, std::enable_if_t<
    is_bpf_serializable<V>::value
>> : std::true_type {};

} // namespace bpf_detail


// Type-erased callback for kv_set syscall
using KVSetFunc = std::function<void(const std::string&, const BpfKV&)>;

// Arguments passed to BpfCallback::OnCall
struct BpfCallArgs {
    std::string pb_data;    // serialized protobuf
    KVSetFunc kv_set;       // write-back callback
};

class vm;
// BpfCallback - hook callback that runs BPF programs in a sandboxed VM
class BpfCallback : public IHookCallback {
    std::string elf_path;
    uint64_t entry = 0;
    std::shared_ptr<vm> v;
public:
    BpfCallback(const std::string& elf_path, std::string& msg);

    // args must point to a BpfCallArgs
    void OnCall(void* args) override;

    std::string name() override { return "bpf:" + elf_path; }
};

#endif // BPF_BRIDGE_H__
