//
// bpf_syscall.h — sproxy bridge 的 BPF 扩展 syscall ABI（src_reg=0）
//
// sproxy 注入给 BPF hook 程序的扩展 syscall 编号空间，与 bpfvm 自身的 POSIX
// syscall（MMAP/EXIT/...）是不同的编号集——sproxy 的 BPF 程序只跑在 sproxy 的
// VM 实例里，由 bpf_bridge.cpp 的 BpfSyscallHandler 处理。
//
//   guest 侧（src/hook/include/bpf.h）声明 kv_set/bpf_log 函数指针，编译时绑
//   到 BPF_CALL_KV_SET / BPF_CALL_LOG 立即数；
//   host 侧（bpf_bridge.cpp）的 BpfSyscallHandler::syscall 按 src_reg=0 的 imm
//   dispatch 到对应处理。
//

#ifndef BPF_SYSCALL_H
#define BPF_SYSCALL_H

// 本头同时被 guest BPF 程序（-target bpf -nostdinc，经 include/bpf.h 引入）与
// host C++（bpf_bridge.cpp）使用，故不依赖 <stdint.h>，用内置 unsigned int。
#define BPF_CALL_BASE 0x10000u
#define BPF_CALL_ID(id) (BPF_CALL_BASE + (unsigned int)(id))
#define BPF_CALL_TO_ID(call) ((unsigned int)(call) - BPF_CALL_BASE)

// sproxy bridge 扩展 syscall 编号
#define BPF_SYS_KV_SET  1   // kv_set(key_ptr, key_len, val_ptr, val_len, type)
#define BPF_SYS_LOG     2   // bpf_log(level, msg_ptr, msg_len)

#define BPF_CALL_KV_SET BPF_CALL_ID(BPF_SYS_KV_SET)
#define BPF_CALL_LOG    BPF_CALL_ID(BPF_SYS_LOG)

#endif //BPF_SYSCALL_H
