#ifndef BPF_BRIDGE_H__
#define BPF_BRIDGE_H__

#include "reflect.h"
#include "hook_callback.h"
#include "bpfvm/insn.h"

#include <array>
#include <string>
#include <string_view>
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
//
// 单缓冲直写：嵌套 LEN 字段先写 5 字节定宽 varint 占位、内容写完回填，
// 全程只触碰一个缓冲，不产生中间 string（定宽 varint 是合法编码，解码端无感）。

class PbWriter {
    std::string& buf;
    char stage[64];
    size_t n = 0;

    void flush() {
        if (n) {
            buf.append(stage, n);
            n = 0;
        }
    }
    void put(char c) {
        if (n == sizeof(stage)) flush();
        stage[n++] = c;
    }
public:
    explicit PbWriter(std::string& out) : buf(out) {}

    size_t size() const { return buf.size() + n; }
    void truncate(size_t len) {
        flush();
        buf.resize(len);
    }

    void varint(uint64_t v) {
        while (v > 0x7F) {
            put((char)((v & 0x7F) | 0x80));
            v >>= 7;
        }
        put((char)(v & 0x7F));
    }
    void tag(uint32_t field, uint32_t wire) {
        varint(((uint64_t)field << 3) | wire);
    }
    // LEN 字段：返回占位偏移（tag 之后），内容写完后 end_len 回填实际长度
    size_t begin_len(uint32_t field) {
        flush();
        char tmp[12];
        size_t k = 0;
        uint64_t t = ((uint64_t)field << 3) | 2;
        while (t > 0x7F) {
            tmp[k++] = (char)((t & 0x7F) | 0x80);
            t >>= 7;
        }
        tmp[k++] = (char)t;
        size_t tag_len = k;
        for (int i = 0; i < 5; i++) tmp[k++] = '\x80';
        tmp[k - 1] = '\0';
        size_t off = buf.size();
        buf.append(tmp, k);
        return off + tag_len;
    }
    void end_len(size_t off) {
        flush();
        size_t len = buf.size() - off - 5;
        for (int i = 0; i < 4; i++) {
            buf[off + i] = (char)((len & 0x7F) | 0x80);
            len >>= 7;
        }
        buf[off + 4] = (char)(len & 0x7F);
    }
    void varint_field(uint32_t field, uint64_t v) {
        tag(field, 0);
        varint(v);
    }
    void bytes_field(uint32_t field, const void* data, size_t len) {
        tag(field, 2);
        varint(len);
        if (n + len <= sizeof(stage)) {
            memcpy(stage + n, data, len);
            n += len;
        } else {
            flush();
            buf.append((const char*)data, len);
        }
    }
};


// ============ IVisitor-based visitors for virtual reflect ============

// PBSerializeVisitor: reflect 树直写进 PbWriter。
// map/vector 元素经 push_map_key + leaf(name=nullptr) 到达，叶子名回退取 pending_map_key_。
class PBSerializeVisitor : public IVisitor {
    static constexpr size_t MAX_DEPTH = 64;
    PbWriter& w;
    struct Nest {
        size_t entry_off, value_off, kvmap_off;  // begin_len 占位（root/透明层无效）
        size_t start;                            // entry 占位前的缓冲长度，空对象回退目标
        size_t body;                             // entry 占位后的缓冲长度，空对象判空基准
        bool root;                               // push(nullptr) 且栈底：根标记；无名非根：透明层
    };
    Nest stack_[MAX_DEPTH];
    size_t depth_ = 0;
    std::string pending_map_key_;

    const char* entry_name(const char* name) const {
        if (name) return name;
        return pending_map_key_.empty() ? nullptr : pending_map_key_.c_str();
    }
public:
    explicit PBSerializeVisitor(PbWriter& writer) : w(writer) {}

    Mode mode() const override { return Mode::Serialize; }

    void push(const char* name) override {
        const char* n = (name || depth_ != 0) ? entry_name(name) : nullptr;
        if (depth_ >= MAX_DEPTH) { depth_++; return; }  // 超深嵌套按透明层处理，叶子仍写入父层，不占槽
        Nest scope{0, 0, 0, w.size(), 0, !n};
        if (n) {
            scope.entry_off = w.begin_len(1);
            w.bytes_field(1, n, strlen(n));
            scope.value_off = w.begin_len(2);
            scope.kvmap_off = w.begin_len(5);
            scope.body = w.size();
        }
        stack_[depth_++] = scope;
    }
    void pop() override {
        if (depth_ > MAX_DEPTH) { depth_--; return; }
        Nest s = stack_[--depth_];
        if (s.root) return;
        if (w.size() == s.body) {
            w.truncate(s.start);
            return;
        }
        w.end_len(s.kvmap_off);
        w.end_len(s.value_off);
        w.end_len(s.entry_off);
    }
    void push_map_key(const std::string& key) override { pending_map_key_ = key; }
    void pop_map_key() override { pending_map_key_.clear(); }

    // 叶子直接写进当前打开的 KVMap 体
    void leaf_i64(const char* name, int64_t& val) override {
        const char* n = entry_name(name);
        if (!n) return;
        size_t e = w.begin_len(1);
        w.bytes_field(1, n, strlen(n));
        size_t v = w.begin_len(2);
        w.varint_field(1, (uint64_t)val);
        w.end_len(v);
        w.end_len(e);
    }
    void leaf_u64(const char* name, uint64_t& val) override {
        const char* n = entry_name(name);
        if (!n) return;
        size_t e = w.begin_len(1);
        w.bytes_field(1, n, strlen(n));
        size_t v = w.begin_len(2);
        w.varint_field(2, val);
        w.end_len(v);
        w.end_len(e);
    }
    void leaf_str(const char* name, std::string& val) override {
        const char* n = entry_name(name);
        if (!n) return;
        size_t e = w.begin_len(1);
        w.bytes_field(1, n, strlen(n));
        size_t v = w.begin_len(2);
        w.bytes_field(3, val.data(), val.size());
        w.end_len(v);
        w.end_len(e);
    }
    void leaf_cstr(const char* name, char* val, size_t maxlen) override {
        const char* n = entry_name(name);
        if (!n) return;
        size_t e = w.begin_len(1);
        w.bytes_field(1, n, strlen(n));
        size_t v = w.begin_len(2);
        w.bytes_field(3, val, strnlen(val, maxlen));
        w.end_len(v);
        w.end_len(e);
    }
    void leaf_blob(const char* name, void* data, size_t len) override {
        const char* n = entry_name(name);
        if (!n) return;
        size_t e = w.begin_len(1);
        w.bytes_field(1, n, strlen(n));
        size_t v = w.begin_len(2);
        w.bytes_field(4, data, len);
        w.end_len(v);
        w.end_len(e);
    }

    // Read-only leaf handlers → same serialization
    void leaf_ro_i64(const char* name, int64_t val) override {
        int64_t mut = val; leaf_i64(name, mut);
    }
    void leaf_ro_u64(const char* name, uint64_t val) override {
        uint64_t mut = val; leaf_u64(name, mut);
    }
    void leaf_ro_str(const char* name, const std::string& val) override {
        leaf_str(name, const_cast<std::string&>(val));
    }
    void leaf_ro_blob(const char* name, const void* data, size_t len) override {
        leaf_blob(name, const_cast<void*>(data), len);
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
    PBSetFieldVisitor(std::string_view prefix, const std::string& key, const BpfKV& kv)
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

// serialize_value_body: 把单个值写成 Value 消息体（不含外层长度），调用方负责 begin_len/end_len 包装
template<typename T>
void serialize_value_body(PbWriter& w, const T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_array_v<Raw> && std::is_same_v<std::remove_extent_t<Raw>, char>) {
        w.bytes_field(3, val, strnlen(val, std::extent_v<Raw>));
    } else if constexpr (std::is_same_v<Raw, std::string>) {
        w.bytes_field(3, val.data(), val.size());
    } else if constexpr (std::is_same_v<Raw, const char*> || std::is_same_v<Raw, char*>) {
        const char* s = val ? val : "";
        w.bytes_field(3, s, strlen(s));
    } else if constexpr (is_byte_span<Raw>::value) {
        w.bytes_field(4, val.data(), val.size_bytes());
    } else if constexpr (std::is_enum_v<Raw>) {
        using Underlying = std::underlying_type_t<Raw>;
        serialize_value_body(w, static_cast<Underlying>(val));
    } else if constexpr (std::is_signed_v<Raw> && std::is_integral_v<Raw>) {
        w.varint_field(1, (uint64_t)(int64_t)val);
    } else if constexpr (std::is_unsigned_v<Raw> && std::is_integral_v<Raw>) {
        w.varint_field(2, (uint64_t)val);
    } else if constexpr (is_vector<Raw>::value || is_deque<Raw>::value
                         || is_list<Raw>::value || is_set<Raw>::value
                         || is_span<Raw>::value) {
        size_t arr = w.begin_len(6);
        for (const auto& item : val) {
            size_t elem = w.begin_len(1);
            serialize_value_body(w, item);
            w.end_len(elem);
        }
        w.end_len(arr);
    } else if constexpr (is_map<Raw>::value) {
        size_t m = w.begin_len(5);
        for (const auto& [k, v] : val) {
            std::string ks = map_key_to_string(k);
            size_t e = w.begin_len(1);
            w.bytes_field(1, ks.data(), ks.size());
            size_t vv = w.begin_len(2);
            serialize_value_body(w, v);
            w.end_len(vv);
            w.end_len(e);
        }
        w.end_len(m);
    } else if constexpr (std::is_pointer_v<Raw> && !std::is_void_v<std::remove_pointer_t<Raw>>) {
        if (val) serialize_value_body(w, *val);
    } else if constexpr (is_smart_pointer<Raw>::value) {
        if (val) serialize_value_body(w, *val);
    } else if constexpr (is_complete<Raw>::value && (std::is_base_of_v<HookReflectable, Raw> || has_reflect<Raw>::value)) {
        // reflect(IVisitor&) dispatch: virtual for HookReflectable, direct for has_reflect
        size_t pos = w.size();
        size_t m = w.begin_len(5);
        size_t body = w.size();
        PBSerializeVisitor sv(w);
        sv.push(nullptr);
        const_cast<Raw&>(val).reflect(sv);
        sv.pop();
        if (w.size() == body) w.truncate(pos);  // 空 reflect 对象不输出 field 5
        else w.end_len(m);
    } else if constexpr (is_blob_aggregate<Raw>::value) {
        w.bytes_field(4, &val, sizeof(Raw));
    } else {
        static_assert(dependent_false<Raw>::value,
            "Unsupported BPF leaf type in reflect tree");
    }
}

// ============ HOOK_BPF 参数名：编译期规整与排序 ============
//
// 宏展开处的参数名是字符串字面量，规整（去空白与 &/*、'->'→'.'）与按字典序
// 排序均在编译期完成，排序置换以类类型 NTTP 进入 Trigger：同前缀参数在流式
// 写入时天然相邻，前缀合并不依赖参数声明顺序，线序恒为字典序。
constexpr size_t HOOK_NAME_MAX = 64;

template<size_t N>
constexpr std::array<char, HOOK_NAME_MAX> norm_name(const char (&s)[N]) {
    std::array<char, HOOK_NAME_MAX> out{};
    size_t end = N - 1;  // 不含 '\0'
    while (end > 0 && (s[end-1] == ' ' || s[end-1] == '\t')) end--;
    size_t b = 0;
    while (b < end && (s[b] == ' ' || s[b] == '\t' || s[b] == '&' || s[b] == '*')) b++;
    size_t o = 0;
    for (size_t k = b; k < end && o + 1 < HOOK_NAME_MAX; k++) {
        if (s[k] == '-' && k + 1 < end && s[k+1] == '>') { out[o++] = '.'; k++; }
        else out[o++] = s[k];
    }
    return out;
}

template<size_t Cnt>
struct Names {
    std::array<std::array<char, HOOK_NAME_MAX>, Cnt> names{};
    std::array<size_t, Cnt> perm{};

    static constexpr int cmp(const std::array<char, HOOK_NAME_MAX>& a,
                             const std::array<char, HOOK_NAME_MAX>& b) {
        for (size_t i = 0; i < HOOK_NAME_MAX; i++) {
            if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
            if (a[i] == '\0') return 0;
        }
        return 0;
    }
    template<typename... S>
    constexpr Names(S&&... s) : names{norm_name(s)...} {
        for (size_t i = 0; i < Cnt; i++) perm[i] = i;
        for (size_t i = 1; i < Cnt; i++) {
            size_t k = perm[i], j = i;
            for (; j > 0 && cmp(names[k], names[perm[j-1]]) < 0; j--) perm[j] = perm[j-1];
            perm[j] = k;
        }
    }
    // 某名字是另一名字的祖先路径（如 obj 与 obj.field）：流式写入会产生
    // 同 key 重复条目，被 guest 首匹配解码遮蔽，禁止出现在 HOOK_BPF 参数表里
    constexpr bool has_prefix_conflict() const {
        for (size_t i = 0; i < Cnt; i++) {
            for (size_t j = 0; j < Cnt; j++) {
                if (i == j) continue;
                size_t k = 0;
                while (k < HOOK_NAME_MAX && names[i][k] && names[i][k] == names[j][k]) k++;
                if (names[i][k] == '\0' && (names[j][k] == '.' || names[j][k] == '\0')) return true;
            }
        }
        return false;
    }
    std::string_view name(size_t i) const { return names[i].data(); }
};

// Names 整体作为 NTTP，把排序置换映射成发射用的 index_sequence
template<Names N, typename Seq> struct Permuted;
template<Names N, size_t... Is>
struct Permuted<N, std::index_sequence<Is...>> {
    using type = std::index_sequence<N.perm[Is]...>;
};

// 顶层：参数元组 → KVMap。参数名带点的（如 obj->field 规整后的 "obj.field"）
// 按路径段展开为嵌套 KVMap，相邻的同前缀参数合并进同一层（发射顺序由 Trigger
// 的编译期排序保证同前缀参数相邻）。
template<typename T>
size_t pb_size_hint(const T& val) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (std::is_same_v<Raw, std::string>) {
        return val.size() + 24;
    } else if constexpr (is_byte_span<Raw>::value) {
        return val.size_bytes() + 24;
    } else if constexpr (std::is_array_v<Raw> && std::is_same_v<std::remove_extent_t<Raw>, char>) {
        return std::extent_v<Raw> + 24;
    } else {
        return 24;
    }
}

template<size_t Cnt, typename Tuple, size_t... Is>
void serialize_tuple(std::string& out, const Names<Cnt>& names,
                     const Tuple& t, std::index_sequence<Is...>) {
    out.reserve(out.size() + 96 + (pb_size_hint(std::get<Is>(t)) + ... + 0));
    PbWriter w(out);
    struct Nest {
        size_t entry_off, value_off, kvmap_off;
    };
    std::string_view open_segs[16];   // 已打开的祖先路径段
    Nest open_nests[16]; // 每层的 entry/value/kvmap 占位
    size_t open_count = 0;
    auto close_to = [&](size_t keep) {
        while (open_count > keep) {
            open_count--;
            Nest n = open_nests[open_count];
            w.end_len(n.kvmap_off);
            w.end_len(n.value_off);
            w.end_len(n.entry_off);
        }
    };
    auto emit = [&](size_t i, const auto& val) {
        std::string_view pname = names.name(i);
        std::string_view segs[16];
        size_t seg_count = 0;
        for (size_t b = 0, b15 = 0;;) {
            if (seg_count == 16) {
                segs[15] = pname.substr(b15);  // 超深路径并入末段
                break;
            }
            if (seg_count == 15) b15 = b;
            size_t d = pname.find('.', b);
            if (d == std::string_view::npos) {
                segs[seg_count++] = pname.substr(b);
                break;
            }
            segs[seg_count++] = pname.substr(b, d - b);
            b = d + 1;
        }
        // 末段是 entry key，祖先只到倒数第二段
        size_t common = 0;
        while (common < open_count && common + 1 < seg_count
               && open_segs[common] == segs[common]) {
            common++;
        }
        close_to(common);
        for (size_t s = common; s + 1 < seg_count; s++) {
            Nest n;
            n.entry_off = w.begin_len(1);
            w.bytes_field(1, segs[s].data(), segs[s].size());
            n.value_off = w.begin_len(2);
            n.kvmap_off = w.begin_len(5);
            open_nests[open_count] = n;
            open_segs[open_count] = segs[s];
            open_count++;
        }
        size_t e = w.begin_len(1);
        w.bytes_field(1, segs[seg_count - 1].data(), segs[seg_count - 1].size());
        size_t v = w.begin_len(2);
        serialize_value_body(w, val);
        w.end_len(v);
        w.end_len(e);
    };
    (emit(Is, std::get<Is>(t)), ...);
    close_to(0);
}

// ============ Write-back: kv_set → reflect directly ============

template<typename T>
int set_param(std::string_view name, const std::string& key, const BpfKV& kv, T& val);

// Helper: given a pre-validated index, dispatch set_param on the element
template<typename Elem>
int set_indexed_param(std::string_view name, const std::string& key, const BpfKV& kv,
                      Elem& elem, size_t idx) {
    std::string rest_key = key.substr(key.find(']', name.size() + 1) + 1);
    std::string elem_name = std::string(name) + "[" + std::to_string(idx) + "]";
    if (rest_key.empty()) {
        return set_param(elem_name, key, kv, elem);
    }
    if (rest_key[0] == '.') rest_key = rest_key.substr(1);
    return set_param(elem_name, elem_name + "." + rest_key, kv, elem);
}

// Parse "[idx]" suffix from key starting at name.size(), return parsed index or false
inline bool parse_bracket_index(std::string_view name, const std::string& key, size_t& idx) {
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
int set_param(std::string_view name, const std::string& key, const BpfKV& kv, T& val) {
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
        std::string elem_name = std::string(name) + "[" + map_key_str + "]";
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

template<size_t Cnt, typename Tuple, size_t... Is>
int set_tuple_field(const Names<Cnt>& names, const std::string& key,
                    const BpfKV& kv, Tuple& t, std::index_sequence<Is...>) {
    int result = -ENOENT;
    auto merge = [&result](int r) {
        if (result == 0) return;
        if (r == 0) result = 0;
        else if (r != -ENOENT && result == -ENOENT) result = r;
    };
    (merge(set_param(names.name(Is), key, kv, std::get<Is>(t))), ...);
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
    ElfLoadInfo info{};
    std::shared_ptr<vm> v;
    std::shared_ptr<const vmImage> vmImg;
public:
    BpfCallback(const std::string& elf_path, std::string& msg);

    // args must point to a BpfCallArgs
    void OnCall(void* args) override;

    std::string name() override { return "bpf:" + elf_path; }
};

#endif // BPF_BRIDGE_H__
