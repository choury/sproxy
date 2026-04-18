#ifndef BPF_BRIDGE_H__
#define BPF_BRIDGE_H__

#include "reflect.h"
#include "hook_callback.h"
#include "bpfvm/insn.h"

#include <string>
#include <map>
#include <functional>
#include <type_traits>
#include <cerrno>
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


// ============ IVisitor-based visitors for virtual reflect ============

// PBSerializeVisitor: builds protobuf KVMap from virtual reflect(IVisitor&)
class PBSerializeVisitor : public IVisitor {
    struct Scope {
        std::string name;   // name passed to push(), or map key
        std::string kvmap;  // accumulated protobuf MapEntry bytes
    };
    std::vector<Scope> stack_;
    std::string pending_map_key_;
    std::string* out_;      // final output (top-level result)
public:
    explicit PBSerializeVisitor(std::string& out) : out_(&out) {
        stack_.push_back({"", {}});
    }

    Mode mode() const override { return Mode::Serialize; }

    void push(const char* name) override {
        stack_.push_back({name ? name : "", {}});
    }
    void pop() override {
        Scope s = std::move(stack_.back());
        stack_.pop_back();
        if (s.kvmap.empty() && stack_.size() > 1) return;
        // Serialize child as nested KVMap Value(5) and add to parent
        std::string val_msg;
        if (!s.kvmap.empty()) {
            pb_append_bytes_field(val_msg, 5, s.kvmap.data(), s.kvmap.size());
        }
        std::string entry_name = s.name.empty() ? pending_map_key_ : s.name;
        if (!entry_name.empty() && !val_msg.empty()) {
            pb_append_map_entry(stack_.back().kvmap, entry_name, val_msg);
        } else if (stack_.size() == 1 && !s.kvmap.empty()) {
            // Top-level: move to output
            *out_ = std::move(s.kvmap);
        }
    }
    void push_map_key(const std::string& key) override { pending_map_key_ = key; }
    void pop_map_key() override { pending_map_key_.clear(); }

    // Mutable leaf handlers → serialize to protobuf
    void leaf_i64(const char* name, int64_t& val) override {
        std::string msg;
        pb_append_varint_field(msg, 1, (uint64_t)val);
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
    void leaf_u64(const char* name, uint64_t& val) override {
        std::string msg;
        pb_append_varint_field(msg, 2, val);
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
    void leaf_str(const char* name, std::string& val) override {
        std::string msg;
        pb_append_bytes_field(msg, 3, val.data(), val.size());
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
    void leaf_cstr(const char* name, char* val, size_t maxlen) override {
        std::string msg;
        pb_append_bytes_field(msg, 3, val, strnlen(val, maxlen));
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
    void leaf_blob(const char* name, void* data, size_t len) override {
        std::string msg;
        pb_append_bytes_field(msg, 4, data, len);
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }

    // Read-only leaf handlers → same serialization
    void leaf_ro_i64(const char* name, int64_t val) override {
        int64_t mut = val; leaf_i64(name, mut);
    }
    void leaf_ro_u64(const char* name, uint64_t val) override {
        uint64_t mut = val; leaf_u64(name, mut);
    }
    void leaf_ro_str(const char* name, const std::string& val) override {
        std::string msg;
        pb_append_bytes_field(msg, 3, val.data(), val.size());
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
    void leaf_ro_blob(const char* name, const void* data, size_t len) override {
        std::string msg;
        pb_append_bytes_field(msg, 4, data, len);
        if (name) pb_append_map_entry(stack_.back().kvmap, name, msg);
    }
};

// PBSetFieldVisitor: finds a specific field by key path and writes via virtual reflect
class PBSetFieldVisitor : public IVisitor {
    std::string prefix_;
    const std::string& key_;
    const BpfKV& kv_;
    int result_ = -ENOENT;
    std::string pending_map_key_;

    std::string make_path(const char* name) const {
        if (!name) return prefix_;
        if (prefix_.empty()) return name;
        return prefix_ + "." + name;
    }
    bool matches(const std::string& path) const {
        return path == key_
            || (key_.size() > path.size()
                && key_.compare(0, path.size(), path) == 0
                && (key_[path.size()] == '.' || key_[path.size()] == '['));
    }
public:
    PBSetFieldVisitor(const std::string& prefix, const std::string& key, const BpfKV& kv)
        : prefix_(prefix), key_(key), kv_(kv) {}

    Mode mode() const override { return Mode::SetField; }
    int& result_ref() override { return result_; }
    const std::string& target_key() const override { return key_; }
    std::string current_path() const override { return prefix_; }

    void push(const char* name) override {
        prefix_ = make_path(name);
    }
    void pop() override {
        auto dot = prefix_.rfind('.');
        prefix_ = (dot == std::string::npos) ? "" : prefix_.substr(0, dot);
    }
    void push_map_key(const std::string& k) override {
        pending_map_key_ = k;
        if (!prefix_.empty()) prefix_ += "[" + k + "]";
    }
    void pop_map_key() override {
        auto bracket = prefix_.rfind('[');
        if (bracket != std::string::npos) prefix_ = prefix_.substr(0, bracket);
        pending_map_key_.clear();
    }

    void leaf_i64(const char* name, int64_t& val) override {
        if (result_ == 0) return;
        std::string path = make_path(name);
        if (path != key_) return;
        if (kv_.type != BpfKV::INT64 && kv_.type != BpfKV::UINT64) { result_ = -EINVAL; return; }
        val = kv_.type == BpfKV::INT64 ? kv_.i64 : (int64_t)kv_.u64;
        result_ = 0;
    }
    void leaf_u64(const char* name, uint64_t& val) override {
        if (result_ == 0) return;
        std::string path = make_path(name);
        if (path != key_) return;
        if (kv_.type != BpfKV::UINT64 && kv_.type != BpfKV::INT64) { result_ = -EINVAL; return; }
        val = kv_.type == BpfKV::UINT64 ? kv_.u64 : (uint64_t)kv_.i64;
        result_ = 0;
    }
    void leaf_str(const char* name, std::string& val) override {
        if (result_ == 0) return;
        std::string path = make_path(name);
        if (path != key_) return;
        if (kv_.type != BpfKV::STRING && kv_.type != BpfKV::BYTES) { result_ = -EINVAL; return; }
        val = kv_.str;
        result_ = 0;
    }
    void leaf_cstr(const char* name, char* val, size_t maxlen) override {
        if (result_ == 0) return;
        std::string path = make_path(name);
        if (path != key_) return;
        if (kv_.type != BpfKV::STRING && kv_.type != BpfKV::BYTES) { result_ = -EINVAL; return; }
        if (maxlen == 0) { result_ = -EINVAL; return; }
        strncpy(val, kv_.str.c_str(), maxlen - 1);
        val[maxlen - 1] = '\0';
        result_ = 0;
    }
    void leaf_blob(const char* name, void* data, size_t len) override {
        if (result_ == 0) return;
        std::string path = make_path(name);
        if (path != key_) return;
        if (kv_.type != BpfKV::BYTES || kv_.str.size() != len) { result_ = -EINVAL; return; }
        memcpy(data, kv_.str.data(), len);
        result_ = 0;
    }

    void check_readonly(const char* name) {
        if (matches(make_path(name))) result_ = -EACCES;
    }
    void leaf_ro_i64(const char* name, int64_t) override { check_readonly(name); }
    void leaf_ro_u64(const char* name, uint64_t) override { check_readonly(name); }
    void leaf_ro_str(const char* name, const std::string&) override { check_readonly(name); }
    void leaf_ro_blob(const char* name, const void*, size_t) override { check_readonly(name); }
};

// ============ Serialize: reflect → nested protobuf ============

// serialize_value: produce a Value message for a single value
template<typename T>
std::string serialize_value(const T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    std::string value_msg;
    if constexpr (std::is_array_v<Raw> && std::is_same_v<std::remove_extent_t<Raw>, char>) {
        pb_append_bytes_field(value_msg, 3, val, strnlen(val, std::extent_v<Raw>));
    } else if constexpr (std::is_same_v<Raw, std::string>) {
        pb_append_bytes_field(value_msg, 3, val.data(), val.size());
    } else if constexpr (std::is_same_v<Raw, const char*> || std::is_same_v<Raw, char*>) {
        const char* s = val ? val : "";
        pb_append_bytes_field(value_msg, 3, s, strlen(s));
    } else if constexpr (is_byte_span<Raw>::value) {
        pb_append_bytes_field(value_msg, 4, val.data(), val.size_bytes());
    } else if constexpr (std::is_enum_v<Raw>) {
        using Underlying = std::underlying_type_t<Raw>;
        return serialize_value(static_cast<Underlying>(val));
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        pb_append_varint_field(value_msg, 1, (uint64_t)(int64_t)val);
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        pb_append_varint_field(value_msg, 2, (uint64_t)val);
    } else if constexpr (is_vector<Raw>::value || is_deque<Raw>::value
                         || is_list<Raw>::value || is_set<Raw>::value
                         || is_span<Raw>::value) {
        // Value field 6 = Array { repeated Value elements = 1 }
        std::string array_msg;
        for (const auto& item : val) {
            std::string elem = serialize_value(item);
            pb_append_bytes_field(array_msg, 1, elem.data(), elem.size());
        }
        pb_append_bytes_field(value_msg, 6, array_msg.data(), array_msg.size());
    } else if constexpr (is_map<Raw>::value) {
        // Value field 5 = KVMap
        std::string kvmap;
        for (const auto& [k, v] : val) {
            std::string v_msg = serialize_value(v);
            pb_append_map_entry(kvmap, ::map_key_to_string(k), v_msg);
        }
        pb_append_bytes_field(value_msg, 5, kvmap.data(), kvmap.size());
    } else if constexpr (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>) {
        if (val) return serialize_value(*val);
    } else if constexpr (is_smart_pointer<Raw>::value) {
        if (val) return serialize_value(*val);
    } else if constexpr (is_complete<Raw>::value && (std::is_base_of_v<HookReflectable, Raw> || has_reflect<Raw>::value)) {
        // reflect(IVisitor&) dispatch: virtual for HookReflectable, direct for has_reflect
        std::string kvmap;
        PBSerializeVisitor sv(kvmap);
        sv.push(nullptr);
        const_cast<Raw&>(val).reflect(sv);
        sv.pop();
        if (!kvmap.empty()) {
            pb_append_bytes_field(value_msg, 5, kvmap.data(), kvmap.size());
        }
    } else if constexpr (is_blob_aggregate<Raw>::value) {
        pb_append_bytes_field(value_msg, 4, &val, sizeof(val));
    } else {
        static_assert(dependent_false<Raw>::value,
            "Unsupported BPF leaf type in reflect tree");
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
    ((root.insert(Is < names.size() ? names[Is] : "arg" + std::to_string(Is), serialize_value(std::get<Is>(t)))), ...);

    for (const auto& kv : root.children) {
        pb_append_map_entry(out, kv.first, kv.second.serialize());
    }
}

// ============ Write-back: kv_set → reflect directly ============

template<typename T>
int set_param(const std::string& name, const std::string& key, const BpfKV& kv, T& val);

// Helper: given a pre-validated index, dispatch set_param on the element
template<typename Elem>
int set_indexed_param(const std::string& name, const std::string& key, const BpfKV& kv,
                       Elem& elem, size_t idx) {
    std::string rest_key = key.substr(key.find(']', name.size() + 1) + 1);
    std::string elem_name = name + "[" + std::to_string(idx) + "]";
    if (rest_key.empty()) {
        return set_param(elem_name, key, kv, elem);
    }
    if (rest_key[0] == '.') rest_key = rest_key.substr(1);
    return set_param(elem_name, elem_name + "." + rest_key, kv, elem);
}

// Parse "[idx]" suffix from key starting at name.size(), return parsed index or false
inline bool parse_bracket_index(const std::string& name, const std::string& key, size_t& idx) {
    if (key.size() <= name.size() || key.compare(0, name.size(), name) != 0
        || key[name.size()] != '[') {
        return false;
    }
    auto bracket_end = key.find(']', name.size() + 1);
    if (bracket_end == std::string::npos) return false;
    std::string idx_str = key.substr(name.size() + 1, bracket_end - name.size() - 1);
    char* endptr = nullptr;
    idx = strtoull(idx_str.c_str(), &endptr, 10);
    return endptr != idx_str.c_str() && *endptr == '\0';
}

template<typename T>
int set_param(const std::string& name, const std::string& key, const BpfKV& kv, T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_const_v<T>) {
        if (key == name || (key.size() > name.size() && key.compare(0, name.size(), name) == 0
                            && (key[name.size()] == '.' || key[name.size()] == '['))) {
            return -EACCES;
        }
        return -ENOENT;
    } else if constexpr (is_byte_span<Raw>::value) {
        if constexpr (std::is_const_v<typename Raw::element_type>) {
            return name == key ? -EACCES : -ENOENT;
        } else {
            if (name != key) return -ENOENT;
            if ((kv.type != BpfKV::STRING && kv.type != BpfKV::BYTES)
                || kv.str.size() != val.size_bytes()) return -EINVAL;
            memcpy(val.data(), kv.str.data(), val.size_bytes());
            return 0;
        }
    } else if constexpr (std::is_same_v<Raw, std::string>) {
        if (name != key) return -ENOENT;
        if (kv.type != BpfKV::STRING && kv.type != BpfKV::BYTES) return -EINVAL;
        val = kv.str;
        return 0;
    } else if constexpr (std::is_array_v<Raw> && std::is_same_v<std::remove_extent_t<Raw>, char>) {
        if (name != key) return -ENOENT;
        if (kv.type != BpfKV::STRING && kv.type != BpfKV::BYTES) return -EINVAL;
        strncpy(val, kv.str.c_str(), sizeof(val) - 1);
        val[sizeof(val) - 1] = '\0';
        return 0;
    } else if constexpr (std::is_enum_v<Raw>) {
        using Underlying = std::underlying_type_t<Raw>;
        Underlying tmp = static_cast<Underlying>(val);
        int r = set_param(name, key, kv, tmp);
        if (r == 0) {
            val = static_cast<Raw>(tmp);
        }
        return r;
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        if (name != key) return -ENOENT;
        if (kv.type != BpfKV::INT64 && kv.type != BpfKV::UINT64) return -EINVAL;
        val = static_cast<T>(kv.type == BpfKV::INT64 ? kv.i64 : (int64_t)kv.u64);
        return 0;
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        if (name != key) return -ENOENT;
        if (kv.type != BpfKV::UINT64 && kv.type != BpfKV::INT64) return -EINVAL;
        val = static_cast<T>(kv.type == BpfKV::UINT64 ? kv.u64 : (uint64_t)kv.i64);
        return 0;
    } else if constexpr (is_vector<Raw>::value || is_deque<Raw>::value || is_span<Raw>::value) {
        size_t idx;
        if (!parse_bracket_index(name, key, idx)) return -ENOENT;
        if (idx >= val.size()) return -EINVAL;
        return set_indexed_param(name, key, kv, val[idx], idx);
    } else if constexpr (is_list<Raw>::value) {
        size_t idx;
        if (!parse_bracket_index(name, key, idx)) return -ENOENT;
        if (idx >= val.size()) return -EINVAL;
        auto it = val.begin();
        std::advance(it, idx);
        return set_indexed_param(name, key, kv, *it, idx);
    } else if constexpr (is_set<Raw>::value) {
        if (key.size() > name.size() && key.compare(0, name.size(), name) == 0
            && key[name.size()] == '[') {
            return -EACCES;
        }
        return -ENOENT;
    } else if constexpr (is_map<Raw>::value) {
        using Key = typename Raw::key_type;
        using Mapped = typename Raw::mapped_type;
        if (key.size() <= name.size() || key.compare(0, name.size(), name) != 0
            || key[name.size()] != '[') {
            return -ENOENT;
        }
        auto bracket_end = key.find(']', name.size() + 1);
        if (bracket_end == std::string::npos) return -EINVAL;
        std::string map_key_str = key.substr(name.size() + 1, bracket_end - name.size() - 1);
        std::string rest_key = key.substr(bracket_end + 1);
        Key map_key{};
        if constexpr (std::is_same_v<Key, std::string>) {
            map_key = map_key_str;
        } else if constexpr (std::is_unsigned_v<Key> && std::is_integral_v<Key>) {
            char* endptr = nullptr;
            unsigned long long parsed = strtoull(map_key_str.c_str(), &endptr, 10);
            if (endptr == map_key_str.c_str() || *endptr != '\0') return -EINVAL;
            map_key = static_cast<Key>(parsed);
        } else if constexpr (std::is_signed_v<Key> && std::is_integral_v<Key>) {
            char* endptr = nullptr;
            long long parsed = strtoll(map_key_str.c_str(), &endptr, 10);
            if (endptr == map_key_str.c_str() || *endptr != '\0') return -EINVAL;
            map_key = static_cast<Key>(parsed);
        } else {
            return -EINVAL;
        }
        std::string elem_name = name + "[" + map_key_str + "]";
        if (rest_key.empty()) {
            if constexpr (std::is_default_constructible_v<Mapped>) {
                auto [it, inserted] = val.try_emplace(map_key);
                int r = set_param(elem_name, key, kv, it->second);
                if (r == 0) return 0;
                if (inserted) val.erase(it);
                return r;
            }
            return -EACCES;
        }
        if (rest_key[0] == '.') rest_key = rest_key.substr(1);
        auto it = val.find(map_key);
        if (it == val.end()) return -ENOENT;
        return set_param(elem_name, elem_name + "." + rest_key, kv, it->second);
    } else if constexpr (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>) {
        if (!val) return -ENOENT;
        return set_param(name, key, kv, *val);
    } else if constexpr (is_smart_pointer<Raw>::value) {
        if (!val) return -ENOENT;
        return set_param(name, key, kv, *val);
    } else if constexpr (is_complete<Raw>::value && (std::is_base_of_v<HookReflectable, Raw> || has_reflect<Raw>::value)) {
        // reflect(IVisitor&) dispatch: virtual for HookReflectable, direct for has_reflect
        PBSetFieldVisitor sfv(name, key, kv);
        const_cast<Raw&>(val).reflect(sfv);
        return sfv.result_ref();
    } else if constexpr (is_blob_aggregate<Raw>::value) {
        if (name != key) return -ENOENT;
        if (kv.type != BpfKV::BYTES || kv.str.size() != sizeof(Raw)) return -EINVAL;
        memcpy(&val, kv.str.data(), sizeof(Raw));
        return 0;
    } else {
        static_assert(dependent_false<Raw>::value,
            "Unsupported BPF leaf type in reflect tree");
    }
}

template<typename Tuple, size_t... Is>
int set_tuple_field(const std::vector<std::string>& names, const std::string& key,
                     const BpfKV& kv, Tuple& t, std::index_sequence<Is...>) {
    int result = -ENOENT;
    auto merge = [&result](int r) {
        if (result == 0) return;
        if (r == 0) result = 0;
        else if (r != -ENOENT && result == -ENOENT) result = r;
    };
    (merge(set_param(Is < names.size() ? names[Is] : "arg" + std::to_string(Is),
                     key, kv, std::get<Is>(t))), ...);
    return result;
}

// ============ Compile-time serializability check ============

template<typename T, typename = void>
struct is_bpf_serializable : std::false_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<std::is_integral_v<std::remove_cv_t<std::remove_reference_t<T>>>>> : std::true_type {};
template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<std::is_enum_v<std::remove_cv_t<std::remove_reference_t<T>>>>> : std::true_type {};
template<> struct is_bpf_serializable<std::string> : std::true_type {};
template<> struct is_bpf_serializable<const char*> : std::true_type {};
template<> struct is_bpf_serializable<char*> : std::true_type {};
template<size_t N> struct is_bpf_serializable<char[N]> : std::true_type {};
template<size_t N> struct is_bpf_serializable<const char[N]> : std::true_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<
    is_blob_aggregate<std::remove_cv_t<std::remove_reference_t<T>>>::value
>> : std::true_type {};

template<typename T>
struct is_bpf_serializable<T, std::enable_if_t<
    has_reflect<std::remove_cv_t<std::remove_reference_t<T>>>::value
    && !std::is_integral_v<std::remove_cv_t<std::remove_reference_t<T>>>
    && !std::is_array_v<std::remove_cv_t<std::remove_reference_t<T>>>
    && !is_blob_aggregate<std::remove_cv_t<std::remove_reference_t<T>>>::value
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

template<typename T, typename A>
struct is_bpf_serializable<std::deque<T, A>, std::enable_if_t<
    is_bpf_serializable<T>::value
>> : std::true_type {};

// map<string, V> where V is serializable
template<typename V, typename C, typename A>
struct is_bpf_serializable<std::map<std::string, V, C, A>, std::enable_if_t<
    is_bpf_serializable<V>::value
>> : std::true_type {};

template<typename T, typename A>
struct is_bpf_serializable<std::list<T, A>, std::enable_if_t<
    is_bpf_serializable<T>::value
>> : std::true_type {};

template<typename T, typename C, typename A>
struct is_bpf_serializable<std::set<T, C, A>, std::enable_if_t<
    is_bpf_serializable<T>::value
>> : std::true_type {};

template<typename T, std::size_t E>
struct is_bpf_serializable<std::span<T, E>, std::enable_if_t<
    is_bpf_serializable<std::remove_cv_t<T>>::value
>> : std::true_type {};

template<typename K, typename V, typename C, typename A>
struct is_bpf_serializable<std::map<K, V, C, A>, std::enable_if_t<
    std::is_integral_v<K> && is_bpf_serializable<V>::value
>> : std::true_type {};

} // namespace bpf_detail


// Type-erased callback for kv_set syscall
using KVSetFunc = std::function<int(const std::string&, const BpfKV&)>;

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
