//
// jit_compiler.cpp — JitCompiler template implementation + helper functions.
//

#include "jit_compiler.h"
#include "../insn.h"

#include <queue>
#include <chrono>
#include <cstdio>

#if defined(__x86_64__)
#include "x86_emitter.h"
#elif defined(__aarch64__)
#include "aarch64_emitter.h"
#endif

// ---------------------------------------------------------------------------
// JitCompiler implementation
// ---------------------------------------------------------------------------

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_reg_            = offsetof(vm, reg);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_pc_             = offsetof(vm, pc_);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_flags_          = offsetof(vm, flags);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_tlb_            = offsetof(vm, tlb);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_count_     = offsetof(vm, insn_count);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_limit_     = offsetof(vm, options) + offsetof(vmOptions, insn_limit);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_stack_limit_    = offsetof(vm, options) + offsetof(vmOptions, stack_limit);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_scratch_        = offsetof(vm, jit_scratch);
#pragma GCC diagnostic pop

template<typename EmitterT>
JitCompiler<EmitterT>::JitCompiler() {
    const char* env = getenv("JIT_ENABLE");
    enabled_ = (env == nullptr || strcmp(env, "0") != 0);
    if (const char* e = getenv("JIT_THRESHOLD")) threshold_ = (uint32_t)atoi(e);
    debug_enabled_ = getenv("BPF_DEBUG");

    helpers_.safepoint        = (void*)&helper_safepoint;
    helpers_.push_frame       = (void*)&helper_push_frame;
    helpers_.pop_frame        = (void*)&helper_pop_frame;
    helpers_.do_syscall       = (void*)&helper_do_syscall;
    helpers_.do_softfp        = (void*)&helper_do_softfp;
    helpers_.call_indirect    = (void*)&helper_call_indirect;
    helpers_.call_bpf         = (void*)&helper_call_bpf;
    helpers_.return_to_caller = (void*)&helper_return_to_caller;
    helpers_.resolve_and_cache = (void*)&helper_resolve_and_cache;
    helpers_.mmu              = (void*)&helper_mmu;
    helpers_.mmu_w            = (void*)&helper_mmu_w;
}

template<typename EmitterT>
JitCompiler<EmitterT>::~JitCompiler() {
    for (auto& [pc, entry] : entries_) {
        if (entry.kind == JitEntryKind::Compiled && entry.code) {
            munmap(entry.code, entry.code_size);
            entry.code = nullptr;
        }
    }
}

// ---------------------------------------------------------------------------
// JIT control-flow helpers (called from JIT-generated code)
// ---------------------------------------------------------------------------

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_safepoint(vm* v) {
    uint64_t saved_pc = v->pc_;
    if (!v->safepoint()) {
        return 1;
    }
    if (v->pc_ != saved_pc) {
        return 1;
    }
    return 0;
}

template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_push_frame(vm* v, uint64_t ret_addr) {
    return v->push_frame(ret_addr);
}

template<typename EmitterT>
uint64_t JitCompiler<EmitterT>::helper_pop_frame(vm* v) {
    return v->pop_frame();
}

template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_do_syscall(vm* v, uint32_t call_id) {
    uint64_t saved_pc = v->pc_;
    // do_syscall 内部已检测 VM_EXITED|VM_KILLED 并据此返回 false，无需在此补设 flag。
    if (!v->do_syscall(call_id)) {
        if (v->pc_ == saved_pc) v->pc_ += sizeof(bpf_insn);
        return false;
    }
    if (v->pc_ != saved_pc) {
        // pc 被改（如 longjmp）。置 VM_JIT_ABORT，让调用链各层 .cont 的 flag-check
        // 级联 vm_exit，最终由 step() 接管新 pc。safepoint() 清此位。
        v->flags.fetch_or(vm::VM_JIT_ABORT, std::memory_order_release);
        v->pc_ += sizeof(bpf_insn);
        return false;
    }
    // ERESTARTSYS：可重启 syscall 被信号打断。pc 保持 = saved_pc（syscall 指令）,不推进
    // 此判定必须在下面"推进 pc"的 flag 退出分支之前：重启场景下 VM_SIGNAL_PENDING
    // 必然同时置位（信号入队即设），若先命中则会错误推进 pc。
    if (v->restart_syscall_pc_ != 0) {
        return false;
    }
    // 其余 flag（退出/被杀/停止/待决信号）一律推进 pc 越过 syscall 指令并退出 JIT：
    uint32_t f = v->flags.load(std::memory_order_acquire);
    if (f & (vm::VM_EXITED | vm::VM_KILLED | vm::VM_STOPPED | vm::VM_SIGNAL_PENDING)) {
        v->pc_ += sizeof(bpf_insn);
        return false;
    }
    return true;
}

// FP 虚拟指令的 JIT 回退：do_softfp 只写 r0、不改 pc、不会导致 VM exit，
template<typename EmitterT>
bool JitCompiler<EmitterT>::helper_do_softfp(vm* v, uint32_t call_id) {
    v->do_softfp(call_id);
    return true;
}

template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target) {
    if (!v->push_frame(ret_gpa)) {
        return;
    }
    if (!v->mmu(target)) {
        v->log_mem_violation("call", target);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return;
    }
    v->pc_ = target;
}

template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_bpf(vm* v, uint64_t ret_gpa, uint64_t callee_gpa) {
    if (!v->push_frame(ret_gpa)) {
        v->flags.fetch_or(vm::VM_EXITED, std::memory_order_release);
        return;
    }
    if (!v->mmu(callee_gpa)) {
        v->log_mem_violation("call", callee_gpa);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return;
    }
    v->pc_ = callee_gpa;
}

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_return_to_caller(vm* v, uint64_t ret_gpa) {
    if (!v->mmu(ret_gpa)) {
        v->log_mem_violation("return", ret_gpa);
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return -1;
    }
    v->pc_ = ret_gpa;
    return 0;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_resolve_and_cache(vm* v, uint64_t callee_gpa, uint64_t* slot) {
    // inline cache miss 慢路径。push_frame 已由 JIT 内联完成，这里查 callee：命中填槽并
    //   返回 entry_fast 入口；未编译则 v->pc_=callee_gpa 返回 nullptr（回 step() 编译）。
    void* target = v->jit->resolve_call(v, callee_gpa);
    if (target) {
        *slot = (uint64_t)target;
        return target;
    }
    v->pc_ = callee_gpa;
    return nullptr;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

// resolve_call — 由 helper_resolve_and_cache（cache miss 慢路径）调用，返回 callee 的
//   entry_fast 入口；未编译返回 nullptr。

template<typename EmitterT>
void* JitCompiler<EmitterT>::resolve_call(vm* /*v*/, uint64_t callee_gpa) {
    auto it = entries_.find(callee_gpa);
    if (it == entries_.end()) return nullptr;
    auto& f = it->second;
    if (f.kind != JitEntryKind::Compiled) return nullptr;
    return (char*)f.code + f.entry_fast_offset;
}

// ---------------------------------------------------------------------------
// discover_reachable: BFS to find all reachable BPF instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
std::vector<bool> JitCompiler<EmitterT>::discover_reachable(
    const bpf_insn* start, int seg_limit,
    std::vector<bool>& back_edge_targets,
    std::vector<uint32_t>& loop_body_sizes,
    int& func_size)
{
    func_size = 0;
    if (seg_limit <= 0) return {};

    std::vector<bool> reachable(seg_limit, false);
    back_edge_targets.assign(seg_limit, false);
    // 回边稀疏记录：(target, src)。绝大多数 pc 不是回边 target
    // 改为只在遇到回边时 push，BFS 后聚合。
    std::vector<std::pair<int,int>> back_edges;
    int max_reached = -1;

    std::queue<int> q;
    auto enqueue = [&](int idx) {
        if (idx >= 0 && idx < seg_limit && !reachable[idx]) {
            reachable[idx] = true;
            if (idx > max_reached) max_reached = idx;
            q.push(idx);
        }
    };

    // 记录从 i 到 target 的跳转：标记回边并更新循环体大小估计
    auto jump = [&](int i, int target) {
        if (target >= 0 && target < seg_limit) {
            if (target <= i) {
                back_edge_targets[target] = true;
                back_edges.emplace_back(target, i);
            }
            enqueue(target);
        }
    };

    enqueue(0);

    while (!q.empty()) {
        int i = q.front();
        q.pop();
        const bpf_insn* insn = start + i;
        uint8_t cls = insn->code & 0x07;
        uint8_t op = insn->code & 0xf0;

        int next = i + 1;

        switch (cls) {
        case BPF_LD:
            if ((insn->code & 0xe0) == BPF_IMM && (insn->code & 0x18) == BPF_DW) {
                next = i + 2;
            }
            enqueue(next);
            break;

        case BPF_JMP:
            if (op == BPF_JA) {
                jump(i, i + 1 + insn->off);
            } else if (op == BPF_CALL) {
                enqueue(next);
            } else if (op == BPF_EXIT) {
            } else {
                jump(i, i + 1 + insn->off);
                enqueue(next);
            }
            break;

        case BPF_JMP32:
            if (op == BPF_JA) {
                jump(i, i + 1 + insn->imm);
            } else {
                jump(i, i + 1 + insn->off);
                enqueue(next);
            }
            break;

        default:
            enqueue(next);
            break;
        }
    }

    if (max_reached < 0) return {};

    if (max_reached < seg_limit - 1) {
        const bpf_insn* insn = start + max_reached;
        if ((insn->code & 0x07) == BPF_LD &&
            (insn->code & 0xe0) == BPF_IMM &&
            (insn->code & 0x18) == BPF_DW) {
            max_reached++;
        }
    }

    func_size = max_reached + 1;

    reachable.resize(func_size);
    back_edge_targets.resize(func_size);

    // 计算每个回边目标的循环体大小：同一 target 取最远 src（max 语义）
    loop_body_sizes.assign(func_size, 1);
    for (auto [target, src] : back_edges) {
        int body = src - target + 1;
        if (body > (int)loop_body_sizes[target]) {
            loop_body_sizes[target] = body;
        }
    }

    for (int i = 0; i < func_size - 1; i++) {
        if (reachable[i]) {
            const bpf_insn* insn = start + i;
            if ((insn->code & 0x07) == BPF_LD &&
                (insn->code & 0xe0) == BPF_IMM &&
                (insn->code & 0x18) == BPF_DW) {
                reachable[i + 1] = false;
            }
        }
    }

    return reachable;
}

// ---------------------------------------------------------------------------
// emit_instruction: BPF-level dispatch
// ---------------------------------------------------------------------------

template<typename EmitterT>
bool JitCompiler<EmitterT>::emit_instruction(EmitterT& e, const bpf_insn* entry_pc, uint64_t entry_gpa, int i,
                                               std::vector<JumpPlaceholder>& placeholders,
                                               std::vector<AbortPatchInfo>& abort_patches,
                                               std::vector<size_t>& call_cache_offs,
                                               int& compiled_count) {
    const bpf_insn* insn = entry_pc + i;
    uint8_t cls = insn->code & 0x07;

    switch (cls) {
    case BPF_ALU64:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_alu(insn, true)) return false;
        compiled_count++;
        break;

    case BPF_ALU:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_alu(insn, false)) return false;
        compiled_count++;
        break;

    case BPF_LD:
        if (!e.emit_ld(insn)) return false;
        compiled_count += 2;
        break;

    case BPF_LDX:
        if (insn->dst_reg >= 10) return false;
        if (!e.emit_ldx(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_ST:
        if (!e.emit_st(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_STX:
        if (!e.emit_stx(insn, abort_patches, i)) return false;
        compiled_count++;
        break;

    case BPF_JMP: {
        uint8_t op = insn->code & 0xf0;
        bool is_x = (insn->code & 0x08) == BPF_X;

        if (op == BPF_JA) {
            e.emit_ja(insn, i, placeholders);
            compiled_count++;
        } else if (op == BPF_CALL) {
            if (is_x) {
                uint64_t ret_gpa = entry_gpa + (uint64_t)(i + 1) * sizeof(bpf_insn);
                e.emit_call_indirect(insn, ret_gpa);
                compiled_count++;
            } else if (insn->src_reg == 0) {
                e.emit_call_syscall(insn, i, entry_gpa);
                compiled_count++;
            } else if (insn->src_reg == 1) {
                uint64_t ret_gpa    = entry_gpa + (uint64_t)(i + 1) * sizeof(bpf_insn);
                uint64_t callee_gpa = entry_gpa + (uint64_t)(i + 1 + insn->imm) * sizeof(bpf_insn);
                e.emit_call_bpf(ret_gpa, callee_gpa, abort_patches, i, call_cache_offs);
                compiled_count++;
            } else if (insn->src_reg == 2) {
                // 浮点专用通道：先 JIT 原生（emit_call_softfp），未命中（如 x86 的
                // uint fp<->int 转换）走 emit_call_softfp_slow 回退到 helper_do_softfp。
                if (e.emit_call_softfp(insn)) {
                    compiled_count++;
                } else {
                    e.emit_call_softfp_slow(insn, i, entry_gpa);
                    compiled_count++;
                }
            } else {
                return false;
            }
        } else if (op == BPF_EXIT) {
            e.emit_exit(abort_patches, i);
            compiled_count++;
        } else {
            if (!e.emit_jmp(insn, i, true, placeholders)) return false;
            compiled_count++;
        }
        break;
    }

    case BPF_JMP32: {
        uint8_t op = insn->code & 0xf0;
        if (op == BPF_JA) {
            e.emit_ja32(insn, i, placeholders);
            compiled_count++;
        } else {
            if (!e.emit_jmp(insn, i, false, placeholders)) return false;
            compiled_count++;
        }
        break;
    }

    default:
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// finalize_code
// ---------------------------------------------------------------------------

template<typename EmitterT>
void* JitCompiler<EmitterT>::finalize_code(EmitterT& e) {
    size_t code_size = e.size();
    size_t alloc_size = (code_size + 4095) & ~(size_t)4095;
    void* code_mem = mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code_mem == MAP_FAILED) return nullptr;

    memcpy(code_mem, e.data(), code_size);

    // Flush instruction cache before removing write permission.
    // On AArch64, dc cvau (data cache clean) may require write access on
    // some security-hardened kernels, so do this while pages are still RW.
    __builtin___clear_cache((char*)code_mem, (char*)code_mem + code_size);

    if (mprotect(code_mem, alloc_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code_mem, alloc_size);
        return nullptr;
    }
    return code_mem;
}

// ---------------------------------------------------------------------------
// compile: build a complete JIT function from all reachable instructions
// ---------------------------------------------------------------------------

template<typename EmitterT>
JitEntry* JitCompiler<EmitterT>::compile(vm* v, uint64_t gpa) {
    if (!enabled_) return nullptr;
    // GDB attach 期间（VM_DEBUG_ATTACHED）：跳过 JIT，强制走解释器——解释器每步检查断点/单步，
    if (v->get_flags() & vm::VM_DEBUG_ATTACHED) return nullptr;

    struct Timer {
        bool enable;
        uint64_t& acc;
        std::chrono::high_resolution_clock::time_point start;
        explicit Timer(bool enable_, uint64_t& a) : enable(enable_), acc(a) {
            if (enable) start = std::chrono::high_resolution_clock::now();
        }
        ~Timer() {
            if(!enable) return;
            acc += (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::high_resolution_clock::now() - start).count();
        }
    } timer(debug_enabled_, stats.compile_ns);

    // 一次查找覆盖三类命中：已编译直接返回；failed 永久返回 nullptr；Counting 落到热点判定。
    auto it = entries_.find(gpa);
    if (it != entries_.end()) {
        switch (it->second.kind) {
        case JitEntryKind::Compiled: return &it->second;
        case JitEntryKind::Failed:   return nullptr;
        case JitEntryKind::Counting: break;  // 继续走热点判定
        }
    } else {
        it = entries_.emplace(gpa, JitEntry{}).first;
    }

    // 热点检测：未达阈值的 pc 走解释器（返回 nullptr）。计数器在每次 compile()
    // 调用时递增——step() 单步与 JIT helper_call_bpf 都经过这里，所以循环回边
    // 目标会被反复计数，达到阈值即在循环头编译（OSR：prologue 从 vm->reg[] 加载
    // 解释器当前状态，JIT 接管剩余循环）。冷 pc 永不达阈值，始终走解释器。
    if (threshold_ > 0 && ++it->second.count < threshold_) {
        return nullptr;
    }

    // 记录失败：把当前 entry 标记为 Failed（下次直接命中返回 nullptr，不再重试/计数）。
    auto mark_failed = [&] { it->second.kind = JitEntryKind::Failed; };

    // gpa 是 guest 入口地址；编译期需要 host 指针遍历指令，mmu 取一次（编译期无 CoW）
    const bpf_insn* entry_pc = (const bpf_insn*)v->mmu(gpa);
    if (!entry_pc) return nullptr;
    uint64_t entry_gpa = gpa;

    const bpf_insn* seg_end = nullptr;
    for (auto& m : *v->maps) {
        if (entry_gpa >= m.paddr && entry_gpa < m.paddr + m.size) {
            size_t bytes_remaining = m.size - (size_t)(entry_gpa - m.paddr);
            seg_end = entry_pc + bytes_remaining / sizeof(bpf_insn);
            break;
        }
    }
    if (!seg_end) return nullptr;

    int seg_limit = (int)(seg_end - entry_pc);

    // Discover reachable instructions via BFS
    std::vector<bool> back_edge_targets;
    std::vector<uint32_t> loop_body_sizes;
    int num_insns = 0;
    auto reachable = discover_reachable(entry_pc, seg_limit, back_edge_targets, loop_body_sizes, num_insns);
    // reachable.empty()/num_insns<=0 <=> seg_limit<=0（gpa 距段尾不足一条指令）。
    // gpa 相对段的位置不变、段大小不变，属结构性失败——缓存失败避免每次 step 重跑 BFS。
    if (reachable.empty() || num_insns <= 0) {
        mark_failed();
        return nullptr;
    }

    // 跳转 target 预检（仅 threshold_<=1 启用）：gpa 若是函数中间地址——单次执行的 pc
    // 只在 threshold<=1 下被编译——其相对入口的跳转 target 会越界，patch 阶段必失败。
    // 在昂贵的 emit 之前廉价扫描，越界即判失败，省掉无用的 emit。
    for (int i = 0; threshold_ <= 1 && i < num_insns; i++) {
        if (!reachable[i]) continue;
        const bpf_insn* insn = entry_pc + i;
        uint8_t cls = insn->code & 0x07;
        if (cls != BPF_JMP && cls != BPF_JMP32) continue;
        uint8_t op = insn->code & 0xf0;
        // 只关心会产生 placeholder 的跳转（emit_ja/emit_jmp/emit_ja32）。
        // BPF_CALL/BPF_EXIT 不产生跳转 placeholder。
        if (op == BPF_CALL || op == BPF_EXIT) continue;
        int target;
        if (cls == BPF_JMP32 && op == BPF_JA) {
            target = i + 1 + insn->imm;
        } else {
            target = i + 1 + insn->off;
        }
        // patch 阶段要求 target in [0, num_insns) 且该槽可达（被 emit）。
        if (target < 0 || target >= num_insns || !reachable[target]) {
            mark_failed();
            return nullptr;
        }
    }

    // Set up emitter
    EmitterT e;
    e.set_vm_offsets(off_reg_, off_pc_, off_flags_, off_tlb_, off_stack_limit_, off_scratch_);
    if(debug_enabled_ || v->options.insn_limit != 0) {
        e.set_budget(off_insn_count_, off_insn_limit_, v->options.insn_limit != 0);
    }
    e.set_helpers(helpers_);

    // Emit code
    std::vector<JumpPlaceholder> placeholders;
    std::vector<AbortPatchInfo> abort_patches;
    std::vector<size_t> call_cache_offs;   // inline cache 槽地址占位（imm64）的 buffer 偏移
    std::vector<uint32_t> pc_offsets(num_insns, UINT32_MAX);

    size_t flush_and_exit_offset = e.emit_prologue();

    int compiled_count = 0;
    for (int i = 0; i < num_insns; i++) {
        if (!reachable[i]) continue;
        pc_offsets[i] = (uint32_t)e.size();

        // Safepoint at back-edge targets (loop headers)
        if (back_edge_targets[i]) {
            // 本 safepoint 所在 BPF 指令（循环头）的 guest pc：信号处理返回后应
            // 恢复到此处执行，故把该地址传给 emit_safepoint 写入 vm->pc。
            uint64_t insn_gpa = entry_gpa + (uint64_t)i * sizeof(bpf_insn);
            e.emit_safepoint(loop_body_sizes[i], insn_gpa);
        }

        if (!emit_instruction(e, entry_pc, entry_gpa, i,
                              placeholders, abort_patches, call_cache_offs, compiled_count)) {
            mark_failed();
            return nullptr;
        }
    }

    if (compiled_count == 0) {
        mark_failed();
        return nullptr;
    }

    // Patch jump placeholders
    for (auto& ph : placeholders) {
        if (ph.target_bpf_index < 0 || ph.target_bpf_index >= num_insns ||
            pc_offsets[ph.target_bpf_index] == UINT32_MAX) {
            mark_failed();
            return nullptr;
        }
        size_t target = pc_offsets[ph.target_bpf_index];
        switch (ph.kind) {
        case PlaceholderKind::Conditional:  e.patch_branch_cond(ph.patch_offset, target); break;
        case PlaceholderKind::Unconditional:  e.patch_branch_uncond(ph.patch_offset, target); break;
        }
    }

    // Patch abort jumps to .flush_and_exit
    for (auto& ap : abort_patches) {
        e.patch_branch_cond(ap.jump_offset, flush_and_exit_offset);
    }

    // 复用当前 entry（编译开始前已 emplace，迭代器稳定），承载编译产物；call_cache
    // 落地后取稳定槽地址 patch 进 JIT 代码。
    auto& func = it->second;
    func.gpa = gpa;
    // 每个 call site 有 2 个占位（fast path 读 cache + slow_resolve 传 helper），二者在
    // call_cache_offs 中相邻成对（同一 emit_call_bpf 内连续 push），共用 1 个 cache 槽：
    // 占位 2k/2k+1 -> slot k。
    size_t n_slots = (call_cache_offs.size() + 1) / 2;
    func.call_cache.assign(n_slots, 0);

    // Patch inline cache 槽地址占位 = &func.call_cache[slot_idx]，在 e.data()（RW）上 patch，
    // 随 finalize_code memcpy 进 RX 页——无运行时代码 patch，W^X 保持。
    for (size_t i = 0; i < call_cache_offs.size(); i++) {
        size_t slot_idx = i / 2;
        uint64_t slot_addr = (uint64_t)(uintptr_t)&func.call_cache[slot_idx];
        memcpy(e.data() + call_cache_offs[i], &slot_addr, sizeof(slot_addr));
    }

    // Finalize
    void* code_mem = finalize_code(e);
    if (!code_mem) {
        mark_failed();
        return nullptr;
    }

    stats.jit_compiles++;
    stats.jit_compiled_insns += compiled_count;
    func.code = code_mem;
    func.insn_count = compiled_count;
    func.code_size = (e.size() + 4095) & ~(size_t)4095;
    func.pc_offsets = std::move(pc_offsets);
    func.entry_fast_offset = e.get_entry_fast_offset();  // 由 emit_prologue 生成
    func.kind = JitEntryKind::Compiled;
    return &func;
}

// ---------------------------------------------------------------------------
// Explicit template instantiation
// ---------------------------------------------------------------------------

#if defined(__x86_64__)
template class JitCompiler<X86Emitter>;
#elif defined(__aarch64__)
template class JitCompiler<AArch64Emitter>;
#endif
