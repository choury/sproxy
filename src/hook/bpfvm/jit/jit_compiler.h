//
// jit_compiler.h — Architecture-independent JIT compiler template.
//

#ifndef JIT_COMPILER_H
#define JIT_COMPILER_H

#include "jit.h"

#include <concepts>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <vector>

// Forward declaration
class vm;

// ---------------------------------------------------------------------------
// JitEmitter concept — interface required by JitCompiler from EmitterT
// ---------------------------------------------------------------------------
// Any EmitterT passed to JitCompiler<EmitterT> must satisfy this concept.
// If a method is missing or has the wrong signature, the compiler will
// produce a clear error message indicating which requirement is not met.
// ---------------------------------------------------------------------------
template<typename T>
concept JitEmitter = requires(T& e, const bpf_insn* insn, int idx,
                              std::vector<JumpPlaceholder>& jmps,
                              std::vector<AbortPatchInfo>& aborts,
                              std::vector<size_t>& cache_offs,
                              uint64_t gpa, uint64_t ret_gpa, uint64_t callee_gpa,
                              const HelperTable& helpers,
                              const bpf_insn* entry_pc) {
    // VM state setup
    e.set_vm_offsets(0u, 0u, 0u, 0u, 0u, 0u);
    e.set_budget(0u, 0u, false);
    e.set_helpers(helpers);

    // Prologue / safepoint
    { e.emit_prologue() } -> std::same_as<size_t>;
    e.emit_safepoint(0u, (uint64_t)0);

    // BPF instruction emission
    e.emit_alu(insn, true);
    e.emit_ld(insn);
    e.emit_ldx(insn, aborts, idx);
    e.emit_st(insn, aborts, idx);
    e.emit_stx(insn, aborts, idx);
    e.emit_jmp(insn, idx, true, jmps);
    e.emit_ja(insn, idx, jmps);
    e.emit_ja32(insn, idx, jmps);
    e.emit_call_syscall(insn, idx, gpa);
    e.emit_call_bpf(ret_gpa, callee_gpa, aborts, idx, cache_offs);
    e.emit_call_indirect(insn, gpa);
    e.emit_exit(aborts, idx);

    // Buffer access
    { e.size() } -> std::same_as<size_t>;
    { e.data() } -> std::convertible_to<uint8_t*>;
    // emulate fp instruction (BPF_FP_*) in JIT (x86 SSE/FP) natively, or fall
    // back to helper_do_softfp (e.g. x86 unsigned fp<->int conversion lacks AVX-512).
    { e.emit_call_softfp(insn) } -> std::same_as<bool>;
    e.emit_call_softfp_slow(insn, idx, gpa);

    // Patching
    e.patch_branch_cond(0u, 0u);
    e.patch_branch_uncond(0u, 0u);
};

// ---------------------------------------------------------------------------
// JitCompiler<EmitterT> — architecture-independent compilation logic
// ---------------------------------------------------------------------------

template<typename EmitterT>
class JitCompiler : public JitCompilerBase {
    static_assert(JitEmitter<EmitterT>, "EmitterT must satisfy JitEmitter concept");
public:
    JitCompiler();
    ~JitCompiler();

    // Compile or find a JIT function starting at pc.
    // Returns nullptr if the instruction cannot be JIT-compiled.
    JitEntry* compile(vm* v, uint64_t gpa) override;
    // execve 后失效所有旧 JIT 缓存。注意：与原实现一致，这里只丢弃映射、不 munmap
    // code 页——execve 的 syscall 仍在某段 JIT 代码的调用链中（helper_do_syscall
    // 返回后 JIT .cont 续段还要跑 flag check），此刻 munmap 正在执行的 code 页会
    // segfault。code 页随 JitCompiler 析构（VM 销毁）时统一释放。
    void clear() override { entries_.clear(); }
    // callee 已编译则返回其 entry_fast 入口，否则 nullptr。
    void* resolve_call(vm* v, uint64_t callee_gpa) override;

private:
    // VM field offsets
    static const size_t off_reg_;
    static const size_t off_pc_;
    static const size_t off_flags_;
    static const size_t off_tlb_;
    static const size_t off_insn_count_;
    static const size_t off_insn_limit_;
    static const size_t off_stack_limit_;
    static const size_t off_scratch_;

    // 合并原 functions_/failed_/call_counts_：每条 entry 同时承载编译状态、热点计数、
    // （若已编译）编译产物。compile() 入口由三次哈希查找降为一次。
    std::unordered_map<uint64_t, JitEntry> entries_;
    bool enabled_ = true;
    bool debug_enabled_ = false;
    // 热点检测阈值：每个 pc 的 compile() 调用计数达到阈值才编译。
    uint32_t threshold_ = 100;
    // helper 函数指针表
    HelperTable helpers_;

    // JIT runtime helpers — called from JIT-generated code via function pointer.
    static int helper_safepoint(vm* v);
    static bool helper_push_frame(vm* v, uint64_t ret_addr);
    static uint64_t helper_pop_frame(vm* v);
    static bool helper_do_syscall(vm* v, uint32_t call_id);
    static bool helper_do_softfp(vm* v, uint32_t call_id);
    static void helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target);
    static void helper_call_bpf(vm* v, uint64_t ret_gpa, uint64_t callee_gpa);
    static int helper_return_to_caller(vm* v, uint64_t ret_gpa);
    // inline cache miss 慢路径：查 callee；命中则 *slot=target 返回 target，
    //   未编译则 v->pc_=callee_gpa 返回 nullptr。
    static void* helper_resolve_and_cache(vm* v, uint64_t callee_gpa, uint64_t* slot);
    static void* helper_mmu(vm* v, uint64_t addr, uint64_t size);
    static void* helper_mmu_w(vm* v, uint64_t addr, uint64_t size);

    // Pre-scan: discover all reachable BPF instructions via BFS.
    std::vector<bool> discover_reachable(const bpf_insn* start, int seg_limit,
                                         std::vector<bool>& back_edge_targets,
                                         std::vector<uint32_t>& loop_body_sizes,
                                         int& func_size);

    // Emit a single BPF instruction. Returns false if cannot be compiled.
    bool emit_instruction(EmitterT& e, const bpf_insn* entry_pc, uint64_t entry_gpa, int i,
                          std::vector<JumpPlaceholder>& placeholders,
                          std::vector<AbortPatchInfo>& abort_patches,
                          std::vector<size_t>& call_cache_offs,
                          int& compiled_count);

    // Allocate executable memory (W^X), return pointer or nullptr.
    void* finalize_code(EmitterT& e);
};

#endif // JIT_COMPILER_H
