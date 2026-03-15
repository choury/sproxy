//
// Created by choury on 2026-03-08.
//

#ifndef BPF_CALL_H
#define BPF_CALL_H

#define BPF_CALL_BASE 0x10000u
#define BPF_CALL_ID(id) (BPF_CALL_BASE + (unsigned int)(id))

enum bpf_syscall_id {
    // Extension syscalls for sproxy bridge
    BPF_SYS_KV_SET = 1,    // kv_set(key_ptr, key_len, val_ptr, val_len, type)
    BPF_SYS_LOG,           // bpf_log(level, msg_ptr, msg_len)
};

#define BPF_CALL_KV_SET    BPF_CALL_ID(BPF_SYS_KV_SET)
#define BPF_CALL_LOG       BPF_CALL_ID(BPF_SYS_LOG)

#endif //BPF_CALL_H
