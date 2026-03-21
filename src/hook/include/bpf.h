/*
 * bpf_pb.h - Lightweight protobuf wire format decoder for BPF programs
 *
 * Supports read-only decoding of KVMap protobuf messages.
 * Designed to be compiled into BPF ELF programs (pure C, no dynamic allocation).
 *
 * Wire format reference for KVMap { map<string, Value> entries = 1; }:
 *   - Each map entry is encoded as: field 1 (LEN) containing a sub-message
 *   - Sub-message: field 1 (LEN, key string), field 2 (LEN, Value message)
 *   - Value message: oneof { field 1 (varint, i64), field 2 (varint, u64),
 *                            field 3 (LEN, string), field 4 (LEN, bytes) }
 */
#ifndef BPF_H__
#define BPF_H__

#include "bpf_call.h"

// stddef.h equivalents
typedef unsigned long size_t;
typedef long ptrdiff_t;
#define NULL ((void*)0)
#define offsetof(type, member) __builtin_offsetof(type, member)

// stdint.h equivalents
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long intptr_t;

#define INT64_MIN  (-9223372036854775807L - 1)
#define INT64_MAX  9223372036854775807L
#define UINT64_MAX 18446744073709551615UL

// string.h equivalents
static inline size_t strlen(const char* s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

static inline int memcmp(const void* s1, const void* s2, size_t n) {
    const unsigned char* a = (const unsigned char*)s1;
    const unsigned char* b = (const unsigned char*)s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return a[i] - b[i];
    }
    return 0;
}

static inline void* memcpy(void* dst, const void* src, size_t n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static inline void* memset(void* s, int c, size_t n) {
    unsigned char* p = (unsigned char*)s;
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)c;
    return s;
}


/* Protobuf wire types */
#define PB_WIRE_VARINT  0
#define PB_WIRE_64BIT   1
#define PB_WIRE_LEN     2
#define PB_WIRE_32BIT   5

/* Value types matching the proto oneof */
#define PB_KV_TYPE_I64    1
#define PB_KV_TYPE_U64    2
#define PB_KV_TYPE_STRING 3
#define PB_KV_TYPE_BYTES  4
#define PB_KV_TYPE_KVMAP  5
#define PB_KV_TYPE_ARRAY  6

static inline int pb_decode_varint(const uint8_t* buf, size_t len, uint64_t* out, size_t* consumed) {
    uint64_t result = 0;
    size_t i;
    for (i = 0; i < len && i < 10; i++) {
        result |= (uint64_t)(buf[i] & 0x7F) << (i * 7);
        if (!(buf[i] & 0x80)) {
            *out = result;
            *consumed = i + 1;
            return 0;
        }
    }
    return -1; /* incomplete or too long */
}

static inline int pb_decode_tag(const uint8_t* buf, size_t len,
                                uint32_t* field_number, uint32_t* wire_type, size_t* consumed) {
    uint64_t tag;
    int rc = pb_decode_varint(buf, len, &tag, consumed);
    if (rc != 0) return rc;
    *wire_type = (uint32_t)(tag & 0x07);
    *field_number = (uint32_t)(tag >> 3);
    return 0;
}

/* Skip a field value based on wire type. Returns bytes consumed, or 0 on error. */
static inline size_t pb_skip_field(const uint8_t* buf, size_t len, uint32_t wire_type) {
    size_t consumed;
    uint64_t val;
    switch (wire_type) {
    case PB_WIRE_VARINT:
        if (pb_decode_varint(buf, len, &val, &consumed) != 0) return 0;
        return consumed;
    case PB_WIRE_64BIT:
        return (len >= 8) ? 8 : 0;
    case PB_WIRE_32BIT:
        return (len >= 4) ? 4 : 0;
    case PB_WIRE_LEN:
        if (pb_decode_varint(buf, len, &val, &consumed) != 0) return 0;
        if (consumed + val > len) return 0;
        return consumed + (size_t)val;
    default:
        return 0;
    }
}

typedef struct {
    int type;
    size_t len;     /* Length for strings, KVMaps, arrays, or bytes */
    union {
        const void* ptr; /* Used for STRING, BYTES, KVMAP, ARRAY */
        uint64_t u64;    /* Used for U64 */
        int64_t i64;     /* Used for I64 */
    } val;
} pb_val_t;

/*
 * Decode a Value sub-message.
 * On success: populates out with PB_KV_TYPE_*, appropriate union value, and length.
 */
static inline int pb_decode_value(const uint8_t* pb, size_t len, pb_val_t* out) {
    size_t pos = 0;
    while (pos < len) {
        uint32_t field_number, wire_type;
        size_t tag_len;
        if (pb_decode_tag(pb + pos, len - pos, &field_number, &wire_type, &tag_len) != 0)
            return -1;
        pos += tag_len;

        if (wire_type == PB_WIRE_VARINT && (field_number == 1 || field_number == 2)) {
            uint64_t v;
            size_t vlen;
            if (pb_decode_varint(pb + pos, len - pos, &v, &vlen) != 0)
                return -1;
            pos += vlen;
            out->type = (field_number == 1) ? PB_KV_TYPE_I64 : PB_KV_TYPE_U64;
            if (out->type == PB_KV_TYPE_I64) {
                out->val.i64 = (int64_t)v;
            } else {
                out->val.u64 = v;
            }
            out->len = sizeof(uint64_t);
            return 0;
        } else if (wire_type == PB_WIRE_LEN &&
                   (field_number == 3 || field_number == 4 ||
                    field_number == 5 || field_number == 6)) {
            uint64_t slen;
            size_t slen_consumed;
            if (pb_decode_varint(pb + pos, len - pos, &slen, &slen_consumed) != 0)
                return -1;
            pos += slen_consumed;
            if (pos + slen > len) return -1;
            out->type = (int)field_number; /* 3=STRING, 4=BYTES, 5=KVMAP, 6=ARRAY */
            out->val.ptr = pb + pos;
            out->len = (size_t)slen;
            return 0;
        } else {
            size_t skip = pb_skip_field(pb + pos, len - pos, wire_type);
            if (skip == 0) return -1;
            pos += skip;
        }
    }
    return -1; /* no value found */
}

/*
 * Find a key in KVMap protobuf data.
 * pb/len: the serialized KVMap message.
 * key: null-terminated key string to find.
 * On success: populates out.
 * Returns 0 on success, -1 if not found.
 */
static inline int pb_kv_find_single(const void* pb_data, size_t len, const char* key, pb_val_t* out) {
    const uint8_t* pb = (const uint8_t*)pb_data;
    size_t key_len = strlen(key);
    size_t pos = 0;

    while (pos < len) {
        uint32_t field_number, wire_type;
        size_t tag_len;
        if (pb_decode_tag(pb + pos, len - pos, &field_number, &wire_type, &tag_len) != 0)
            return -1;
        pos += tag_len;

        if (field_number != 1 || wire_type != PB_WIRE_LEN) {
            size_t skip = pb_skip_field(pb + pos, len - pos, wire_type);
            if (skip == 0) return -1;
            pos += skip;
            continue;
        }

        /* Decode the map entry sub-message length */
        uint64_t entry_len;
        size_t entry_len_consumed;
        if (pb_decode_varint(pb + pos, len - pos, &entry_len, &entry_len_consumed) != 0)
            return -1;
        pos += entry_len_consumed;
        if (pos + entry_len > len) return -1;

        const uint8_t* entry = pb + pos;
        size_t epos = 0;
        const uint8_t* found_key = NULL;
        size_t found_key_len = 0;
        const uint8_t* found_value = NULL;
        size_t found_value_len = 0;

        /* Parse entry sub-message: field 1 = key, field 2 = Value */
        while (epos < (size_t)entry_len) {
            uint32_t efn, ewt;
            size_t etl;
            if (pb_decode_tag(entry + epos, (size_t)entry_len - epos, &efn, &ewt, &etl) != 0)
                break;
            epos += etl;

            if (ewt == PB_WIRE_LEN) {
                uint64_t flen;
                size_t flen_consumed;
                if (pb_decode_varint(entry + epos, (size_t)entry_len - epos, &flen, &flen_consumed) != 0)
                    break;
                epos += flen_consumed;
                if (epos + flen > (size_t)entry_len) break;

                if (efn == 1) { /* key */
                    found_key = entry + epos;
                    found_key_len = (size_t)flen;
                } else if (efn == 2) { /* Value message */
                    found_value = entry + epos;
                    found_value_len = (size_t)flen;
                }
                epos += (size_t)flen;
            } else {
                size_t skip = pb_skip_field(entry + epos, (size_t)entry_len - epos, ewt);
                if (skip == 0) break;
                epos += skip;
            }
        }

        /* Check if this entry's key matches the current path part */
        if (found_key != NULL && found_key_len == key_len &&
            memcmp(found_key, key, key_len) == 0 && found_value != NULL) {
            return pb_decode_value(found_value, found_value_len, out);
        }

        pos += (size_t)entry_len;
    }
    return -1; /* key not found */
}

/*
 * Get the i-th element from an Array message.
 * Array = { repeated Value elements = 1; }
 * Returns 0 on success, -1 if index out of range.
 */
static inline int pb_array_get(const void* arr_data, size_t arr_len, size_t index, pb_val_t* out) {
    const uint8_t* pb = (const uint8_t*)arr_data;
    size_t pos = 0;
    size_t cur = 0;

    while (pos < arr_len) {
        uint32_t field_number, wire_type;
        size_t tag_len;
        if (pb_decode_tag(pb + pos, arr_len - pos, &field_number, &wire_type, &tag_len) != 0)
            return -1;
        pos += tag_len;

        if (field_number != 1 || wire_type != PB_WIRE_LEN) {
            size_t skip = pb_skip_field(pb + pos, arr_len - pos, wire_type);
            if (skip == 0) return -1;
            pos += skip;
            continue;
        }

        uint64_t elem_len;
        size_t elem_len_consumed;
        if (pb_decode_varint(pb + pos, arr_len - pos, &elem_len, &elem_len_consumed) != 0)
            return -1;
        pos += elem_len_consumed;
        if (pos + elem_len > arr_len) return -1;

        if (cur == index) {
            return pb_decode_value(pb + pos, (size_t)elem_len, out);
        }
        pos += (size_t)elem_len;
        cur++;
    }
    return -1; /* index out of range */
}

/*
 * Find an element in KVMap or Array protobuf data using a dot/bracket separated path.
 * path: null-terminated path string like "obj.map[aaa].str" or "obj.vec[1]".
 * On success: populates out.
 * Returns 0 on success, -1 if not found.
 */
static inline int pb_kv_find(const void* pb_data, size_t len, const char* path, pb_val_t* out) {
    const uint8_t* current_pb = (const uint8_t*)pb_data;
    size_t current_len = len;
    const char* p = path;
    int current_type = PB_KV_TYPE_KVMAP;
    
    while (*p) {
        // Find the next delimiter ('.' or '[') or end of string
        const char* delim = p;
        while (*delim && *delim != '.' && *delim != '[') {
            delim++;
        }
        
        size_t part_len = delim - p;
        // If part_len is 0, it means the string started with a delimiter.
        // We handle '[' directly below.
        
        pb_val_t p_val;
        
        if (part_len > 0) {
            // It's a key name up to '.' or '['
            if (current_type != PB_KV_TYPE_KVMAP) return -1; // Cannot query by key on non-KVMap
            
            char part_key[64];
            if (part_len >= sizeof(part_key)) return -1; // Key part too long
            
            memcpy(part_key, p, part_len);
            part_key[part_len] = '\0';
            
            if (pb_kv_find_single(current_pb, current_len, part_key, &p_val) != 0) {
                return -1; // Not found
            }
        } else {
            // part_len == 0 means *p must be '['
            if (*p != '[') {
                if (*p == '.') p++; // Ignore consecutive dots or leading dot
                continue;
            }
            p++; // Skip '['
            
            const char* bracket_end = p;
            while (*bracket_end && *bracket_end != ']') bracket_end++;
            if (*bracket_end != ']') return -1; // Unmatched bracket
            
            size_t inner_len = bracket_end - p;
            char inner_key[64];
            if (inner_len >= sizeof(inner_key)) return -1; // Content too long
            memcpy(inner_key, p, inner_len);
            inner_key[inner_len] = '\0';
            
            if (current_type == PB_KV_TYPE_ARRAY) {
                // Parse integer index
                size_t index = 0;
                for (size_t i = 0; i < inner_len; i++) {
                    if (inner_key[i] < '0' || inner_key[i] > '9') return -1; // Invalid index
                    index = index * 10 + (inner_key[i] - '0');
                }
                
                if (pb_array_get(current_pb, current_len, index, &p_val) != 0) {
                    return -1; // Not found
                }
            } else if (current_type == PB_KV_TYPE_KVMAP) {
                // Treat as map key
                if (pb_kv_find_single(current_pb, current_len, inner_key, &p_val) != 0) {
                    return -1; // Not found
                }
            } else {
                return -1; // Cannot index into basic types
            }
            delim = bracket_end;
        }
        
        p = delim;
        if (*p == ']') p++; // Move past ']'
        if (*p == '.') p++; // Move past '.' if any
        if (*p == '\0') {
            // Last part of the path, return the value directly
            *out = p_val;
            return 0;
        }

        // More path segments remain — only container types can be traversed further
        if (p_val.type == PB_KV_TYPE_KVMAP || p_val.type == PB_KV_TYPE_ARRAY) {
            current_pb = (const uint8_t*)p_val.val.ptr;
            current_len = p_val.len;
            current_type = p_val.type;
        } else {
            return -1; // Cannot traverse into scalar types
        }
    }
    return -1;
}

/* Convenience functions */

static inline int64_t pb_kv_get_i64(const void* pb, size_t len, const char* path) {
    pb_val_t val;
    if (pb_kv_find(pb, len, path, &val) != 0)
        return 0;
    if (val.type == PB_KV_TYPE_I64)
        return val.val.i64;
    if (val.type == PB_KV_TYPE_U64)
        return (int64_t)val.val.u64;
    return 0;
}

static inline uint64_t pb_kv_get_u64(const void* pb, size_t len, const char* path) {
    pb_val_t val;
    if (pb_kv_find(pb, len, path, &val) != 0)
        return 0;
    if (val.type == PB_KV_TYPE_U64)
        return val.val.u64;
    if (val.type == PB_KV_TYPE_I64)
        return (uint64_t)val.val.i64;
    return 0;
}

static inline const char* pb_kv_get_str(const void* pb, size_t len, const char* path, size_t* out_len) {
    pb_val_t val;
    if (pb_kv_find(pb, len, path, &val) != 0)
        return (const char*)NULL;
    if (val.type != PB_KV_TYPE_STRING && val.type != PB_KV_TYPE_BYTES)
        return (const char*)NULL;
    if (out_len) *out_len = val.len;
    return (const char*)val.val.ptr;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#ifndef __cplusplus
#pragma GCC diagnostic ignored "-Wint-conversion"
#endif

/* kv_set(key_ptr, key_len, val_ptr, val_len, type)
 * type: 1=INT64, 2=UINT64, 3=STRING, 4=BYTES */
static long (*bpf_kv_set)(const void* key, unsigned long key_len,
                               const void* val, unsigned long val_len,
                               unsigned long type) = (void*)BPF_CALL_KV_SET;

/* bpf_log(level, msg_ptr, msg_len) */
static long (*bpf_log)(unsigned long level, const void* msg, unsigned long msg_len) = (void*)BPF_CALL_LOG;

#pragma GCC diagnostic pop

#endif /* BPF_H__ */
