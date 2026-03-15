/*
 * hook_bpf.c - Test BPF program for hook system
 *
 * Receives protobuf KV data via r1 (pointer) and r2 (length).
 * Reads "a" (int), modifies "b" to a * 100.
 * Returns 0 (allow).
 *
 * Compiled with: clang -target bpf -mcpu=v3|v4 -O1 -std=c11 -nostdinc -fno-builtin -c
 */
// BPF base definitions
#include "include/bpf.h"

/* KV value types: 1=INT64, 2=UINT64, 3=STRING, 4=BYTES */
static void kv_set_int(const char* key, int64_t val) {
    bpf_kv_set(key, strlen(key), &val, sizeof(val), 1);
}

int hook_callback(uint64_t pb_ptr, uint64_t pb_len) {
    const void* pb = (const void*)pb_ptr;

    /* Read "a" from KV */
    int64_t a = pb_kv_get_i64(pb, (unsigned long)pb_len, "a");

    /* Modify: set b = a * 100 */
    kv_set_int("b", a * 100);

    return 0;
}
