//
// jit_compiler.cpp — JitCompiler template implementation + helper functions.
//

#include "jit_compiler.h"
#include "insn.h"

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
const size_t JitCompiler<EmitterT>::off_pc_             = offsetof(vm, pc);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_flags_          = offsetof(vm, flags);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_tlb_            = offsetof(vm, tlb);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_count_     = offsetof(vm, insn_count);
template<typename EmitterT>
const size_t JitCompiler<EmitterT>::off_insn_limit_     = offsetof(vm, options) + offsetof(vmOptions, insn_limit);
#pragma GCC diagnostic pop

template<typename EmitterT>
JitCompiler<EmitterT>::JitCompiler() {
    const char* env = getenv("JIT_ENABLE");
    enabled_ = (env == nullptr || strcmp(env, "0") != 0);
}

template<typename EmitterT>
JitCompiler<EmitterT>::~JitCompiler() {
    for (auto& [pc, f] : functions_) {
        if (f.code) munmap(f.code, f.code_size);
    }
}

// ---------------------------------------------------------------------------
// JIT control-flow helpers (called from JIT-generated code)
// ---------------------------------------------------------------------------

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_safepoint(vm* v) {
    const bpf_insn* saved_pc = v->pc;
    if (!v->safepoint()) {
        return 1;
    }
    if (v->pc != saved_pc) {
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
    const bpf_insn* saved_pc = v->pc;
    bool ok = v->do_syscall(call_id);
    if (!ok) {
        v->flags.fetch_or(vm::VM_EXITED, std::memory_order_release);
        if (v->pc == saved_pc) v->pc++;
        return false;
    }
    if (v->pc != saved_pc) {
        v->pc++;
        return false;
    }
    uint32_t f = v->flags.load(std::memory_order_acquire);
    if (f & (vm::VM_EXITED | vm::VM_KILLED | vm::VM_STOPPED)) {
        v->pc++;
        return false;
    }
    return true;
}

template<typename EmitterT>
void JitCompiler<EmitterT>::helper_call_indirect(vm* v, uint64_t ret_gpa, uint64_t target) {
    if (!v->push_frame(ret_gpa)) {
        return;
    }
    void* host = v->mmu(target);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return;
    }
    v->pc = (const bpf_insn*)host;
}

template<typename EmitterT>
int JitCompiler<EmitterT>::helper_return_to_caller(vm* v, uint64_t ret_gpa) {
    void* host = v->mmu(ret_gpa);
    if (!host) {
        v->flags.fetch_or(vm::VM_KILLED, std::memory_order_release);
        return -1;
    }
    v->pc = (const bpf_insn*)host;
    return 0;
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_slow(addr, (size_t)size);
}

template<typename EmitterT>
void* JitCompiler<EmitterT>::helper_mmu_w(vm* v, uint64_t addr, uint64_t size) {
    return v->mmu_w_slow(addr, (size_t)size);
}

// ---------------------------------------------------------------------------
// Helper table construction
// ---------------------------------------------------------------------------

template<typename EmitterT>
HelperTable JitCompiler<EmitterT>::make_helper_table() const {
    HelperTable h;
    h.safepoint = (void*)&helper_safepoint;
    h.push_frame = (void*)&helper_push_frame;
    h.pop_frame = (void*)&helper_pop_frame;
    h.do_syscall = (void*)&helper_do_syscall;
    h.call_indirect = (void*)&helper_call_indirect;
    h.return_to_caller = (void*)&helper_return_to_caller;
    h.mmu = (void*)&helper_mmu;
    h.mmu_w = (void*)&helper_mmu_w;
    return h;
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
    std::vector<int> max_back_edge_src(seg_limit, -1);
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
                if (i > max_back_edge_src[target]) max_back_edge_src[target] = i;
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

    // 计算每个回边目标的循环体大小
    loop_body_sizes.assign(func_size, 1);
    for (int i = 0; i < func_size; i++) {
        if (back_edge_targets[i] && max_back_edge_src[i] >= 0) {
            loop_body_sizes[i] = max_back_edge_src[i] - i + 1;
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
bool JitCompiler<EmitterT>::emit_instruction(EmitterT& e, vm* v, const bpf_insn* entry_pc, int i,
                                               std::vector<JumpPlaceholder>& placeholders,
                                               std::vector<AbortPatchInfo>& abort_patches,
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
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                e.emit_call_indirect(insn, ret_gpa);
                compiled_count++;
            } else if (insn->src_reg == 0) {
                e.emit_call_syscall(insn, i, entry_pc);
                compiled_count++;
            } else if (insn->src_reg == 1) {
                uint64_t ret_gpa = v->unmmu(entry_pc + i + 1);
                e.emit_call_bpf(insn, i, ret_gpa, entry_pc);
                compiled_count++;
            } else {
                return false;
            }
        } else if (op == BPF_EXIT) {
            e.emit_exit();
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
JitFunction* JitCompiler<EmitterT>::compile(vm* v, const bpf_insn* entry_pc) {
    if (!enabled_) return nullptr;
    auto it = functions_.find(entry_pc);
    if (it != functions_.end()) return &it->second;
    if (failed_.count(entry_pc)) {
        return nullptr;
    }

    auto compile_start = std::chrono::high_resolution_clock::now();
    auto record_compile_time = [&] {
        stats.compile_ns += (uint64_t)std::chrono::duration_cast<
            std::chrono::nanoseconds>(std::chrono::high_resolution_clock::now() - compile_start).count();
    };

    // Find code segment end
    uint64_t entry_gpa = v->unmmu(entry_pc);
    if (!entry_gpa) return nullptr;

    const bpf_insn* seg_end = nullptr;
    for (auto& m : v->maps) {
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
    if (reachable.empty() || num_insns <= 0) { record_compile_time(); return nullptr; }

    // Set up emitter
    bool insn_count_enabled = getenv("BPF_DEBUG") || v->options.insn_limit != 0;
    bool budget_enabled = v->options.insn_limit != 0;
    EmitterT e;
    e.set_vm_offsets(off_reg_, off_pc_, off_flags_, off_tlb_);
    e.set_budget(off_insn_count_, off_insn_limit_, insn_count_enabled, budget_enabled);
    e.set_helpers(make_helper_table());

    // Emit code
    std::vector<JumpPlaceholder> placeholders;
    std::vector<AbortPatchInfo> abort_patches;
    std::vector<uint32_t> pc_offsets(num_insns, UINT32_MAX);

    size_t flush_and_exit_offset = e.emit_prologue();

    int compiled_count = 0;
    for (int i = 0; i < num_insns; i++) {
        if (!reachable[i]) continue;
        pc_offsets[i] = (uint32_t)e.size();

        // Safepoint at back-edge targets (loop headers)
        if (back_edge_targets[i]) {
            e.emit_safepoint(loop_body_sizes[i]);
        }

        if (!emit_instruction(e, v, entry_pc, i,
                              placeholders, abort_patches, compiled_count)) {
            failed_.insert(entry_pc);
            record_compile_time();
            return nullptr;
        }
    }

    if (compiled_count == 0) { failed_.insert(entry_pc); record_compile_time(); return nullptr; }

    // Patch jump placeholders
    for (auto& ph : placeholders) {
        if (ph.target_bpf_index < 0 || ph.target_bpf_index >= num_insns ||
            pc_offsets[ph.target_bpf_index] == UINT32_MAX) {
            failed_.insert(entry_pc);
            record_compile_time();
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

    // Finalize
    void* code_mem = finalize_code(e);
    if (!code_mem) { record_compile_time(); return nullptr; }

    stats.jit_compiles++;
    stats.jit_compiled_insns += compiled_count;
    auto& func = functions_[entry_pc];
    func.code = code_mem;
    func.insn_count = compiled_count;
    func.code_size = (e.size() + 4095) & ~(size_t)4095;
    func.entry_pc = entry_pc;
    func.pc_offsets = std::move(pc_offsets);
    record_compile_time();
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
