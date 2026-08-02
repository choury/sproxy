//
// jit.h — Shared JIT data structures and type aliases.
//

#ifndef JIT_H
#define JIT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>
#include <vector>

struct bpf_insn;
class vm;

// ---------------------------------------------------------------------------
// Jump / call placeholder for deferred patching
// ---------------------------------------------------------------------------
enum class PlaceholderKind : uint8_t {
    Conditional,    // conditional branch placeholder
    Unconditional,  // unconditional branch placeholder
};

struct JumpPlaceholder {
    size_t patch_offset;      // offset in emitter buffer
    int target_bpf_index;     // target BPF instruction index (relative to entry_pc)
    PlaceholderKind kind;
};

struct AbortPatchInfo {
    size_t jump_offset;       // offset of the conditional jump to .vm_exit
    int bpf_index;            // BPF instruction index that may trigger abort
};

// ---------------------------------------------------------------------------
// Context for inline TLB memory access
// ---------------------------------------------------------------------------
struct MemAccessContext {
    std::vector<size_t> miss_jumps;   // TLB miss Jcc offsets → .slow
    std::vector<size_t> abort_jumps;  // null-pointer Jcc offsets → .vm_exit
    size_t slow_start = 0;            // offset of .slow label
    size_t done_offset = 0;           // offset of .done label (after load/store code)
    size_t done_jmp = 0;              // offset of JMP .done (fast path) — needs patching
};

// ---------------------------------------------------------------------------
// JitFunction: one compiled BPF function
// ---------------------------------------------------------------------------
struct JitFunction {
    void* code = nullptr;             // executable entry point
    int insn_count = 0;               // total BPF instructions compiled
    size_t code_size = 0;             // mmap'd allocation size
    uint64_t gpa = 0;                  // first BPF instruction (guest address)
    std::vector<uint32_t> pc_offsets; // BPF index → x86 code offset
};

// ---------------------------------------------------------------------------
// JitStats
// ---------------------------------------------------------------------------
struct JitStats {
    uint64_t jit_compiles = 0;
    uint64_t jit_compiled_insns = 0;
    uint64_t jit_func_runs = 0;
    uint64_t compile_ns = 0;       // total JIT compilation time (ns)
};

// ---------------------------------------------------------------------------
// Helper function pointer table — architecture-independent
// ---------------------------------------------------------------------------
struct HelperTable {
    void* safepoint = nullptr;
    void* push_frame = nullptr;
    void* pop_frame = nullptr;
    void* do_syscall = nullptr;
    void* do_softfp = nullptr;      // (vm*, call_id): FP 虚拟指令的 JIT 回退
    void* call_indirect = nullptr;
    void* call_bpf = nullptr;       // (vm*, ret_gpa, callee_gpa): push_frame + v->pc = callee_gpa
    void* return_to_caller = nullptr;
    void* mmu = nullptr;
    void* mmu_w = nullptr;
};

// ---------------------------------------------------------------------------
// Base class for JIT compilers — virtual dispatch only for compile()
// ---------------------------------------------------------------------------
class JitCompilerBase {
public:
    virtual ~JitCompilerBase() = default;
    virtual JitFunction* compile(vm* v, uint64_t gpa) = 0;
    virtual void clear() {}  // 失效所有已编译的 JIT 缓存（execve 等替换地址空间后必须调用）
    JitStats stats;
};

#endif // JIT_H
