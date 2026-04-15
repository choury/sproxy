/*
 * hook_bpf.c - BPF test program for hook system
 *
 * Receives protobuf KV data via r1 (pointer) and r2 (length).
 * Reads "a" (int), modifies "b" to a * 100.
 * Also verifies bpf_kv_set error return codes.
 * Returns 0 (allow).
 *
 * Compiled with: clang -target bpf -mcpu=v3|v4 -O1 -std=c11 -nostdinc -fno-builtin -c
 */
#include "include/bpf.h"

/* Linux errno values (arch-independent) */
#define ENOENT  2
#define EINVAL  22

static void kv_set_int(const char* key, int64_t val) {
    bpf_kv_set(key, strlen(key), &val, sizeof(val), 1);
}

int hook_callback(uint64_t pb_ptr, uint64_t pb_len) {
    const void* pb = (const void*)pb_ptr;

    /* Read "a" from KV */
    int64_t a = pb_kv_get_i64(pb, pb_len, "a");

    /* Verify error codes from bpf_kv_set */
    int64_t dummy = 0;
    long r;

    /* nonexistent field → -ENOENT */
    r = bpf_kv_set("nonexistent", 11, &dummy, sizeof(dummy), 1);
    if (r != -ENOENT) return 1;

    /* type mismatch (STRING → int field) → -EINVAL */
    r = bpf_kv_set("a", 1, "hello", 5, 3);
    if (r != -EINVAL) return 2;

    /* Modify: set b = a * 100 */
    kv_set_int("b", a * 100);

    return 0;
}
