/*
 * hook_bpf.c - hook 系统的 BPF 程序（入口 hook_callback，r1 = pb 指针，r2 = 长度）
 *
 * 默认编译（无 -D）供 hook_test：读 "a"，验证 bpf_kv_set 错误码，写 b = a * 100。
 * BENCH_READBACK 变体供 hook_test 的嵌套读写回环验证：读 srv 的嵌套路径，
 * 全部读通后写回 srv.port + 1000。
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

#ifdef BENCH_READBACK

int hook_callback(uint64_t pb_ptr, uint64_t pb_len) {
    const void* pb = (const void*)pb_ptr;

    int64_t port = pb_kv_get_i64(pb, pb_len, "srv.port");
    const char* ip = pb_kv_get_str(pb, pb_len, "srv.ips[0]", 0);
    const char* host = pb_kv_get_str(pb, pb_len, "srv.config[host]", 0);

    /* 任一读取失败（返回 0/NULL）则写回 -1，由宿主侧发现 */
    int64_t out = (port == 8080 && ip != NULL && host != NULL) ? port + 1000 : -1;
    kv_set_int("srv.port", out);
    return 0;
}

#else

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

#endif
