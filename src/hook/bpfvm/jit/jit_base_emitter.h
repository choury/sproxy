//
// jit_base_emitter.h — Architecture-independent code emission base.
//

#ifndef JIT_BASE_EMITTER_H
#define JIT_BASE_EMITTER_H

#include <cstdint>
#include <cstring>
#include <vector>
#include "jit.h"

class EmitterBase {
protected:
    std::vector<uint8_t> buf_;

    // VM field offsets (set via set_vm_offsets)
    size_t off_reg_ = 0;
    size_t off_pc_ = 0;
    size_t off_flags_ = 0;
    size_t off_tlb_ = 0;
    size_t off_insn_count_ = 0;
    size_t off_insn_limit_ = 0;
    size_t off_stack_limit_ = 0;   // offsetof(vm, options) + offsetof(vmOptions, stack_limit)
    size_t off_scratch_ = 0;       // offsetof(vm, jit_scratch)
    bool insn_count_enabled_ = false;
    bool budget_enabled_ = false;

    // Helper function pointers (set via set_helpers)：指向 JitCompiler 构造期生成的
    // 同一份 HelperTable，emitter 不再各自拷贝。
    const HelperTable* helpers_ = nullptr;

    // vm_exit offset (set by emit_prologue, used by all emit_* methods)
    size_t vm_exit_offset = 0;
    // entry_fast offset (set by emit_prologue): 跳过 entry-safepoint 的第二入口，供跨函数直接跳转用。
    size_t entry_fast_offset = 0;

public:
    // --- Byte emission ---
    void emit8(uint8_t v) { buf_.push_back(v); }
    void emit16(uint16_t v) {
        buf_.push_back(v & 0xFF);
        buf_.push_back((v >> 8) & 0xFF);
    }
    void emit32(uint32_t v) {
        buf_.push_back(v & 0xFF);
        buf_.push_back((v >> 8) & 0xFF);
        buf_.push_back((v >> 16) & 0xFF);
        buf_.push_back((v >> 24) & 0xFF);
    }
    void emit64(uint64_t v) {
        emit32((uint32_t)v);
        emit32((uint32_t)(v >> 32));
    }

    size_t size() const { return buf_.size(); }
    uint8_t* data() { return buf_.data(); }
    // entry_fast offset 的只读访问，供 compile() 存入 JitEntry。
    size_t get_entry_fast_offset() const { return entry_fast_offset; }

    // --- VM state setup (call before each compilation session) ---
    void set_vm_offsets(size_t off_reg, size_t off_pc, size_t off_flags,
                        size_t off_tlb, size_t off_stack_limit, size_t off_scratch) {
        off_reg_ = off_reg; off_pc_ = off_pc; off_flags_ = off_flags;
        off_tlb_ = off_tlb; off_stack_limit_ = off_stack_limit; off_scratch_ = off_scratch;
    }
    void set_budget(size_t off_insn_count, size_t off_insn_limit, bool budget_enabled) {
        insn_count_enabled_ = true;
        off_insn_count_ = off_insn_count;
        off_insn_limit_ = off_insn_limit;
        budget_enabled_ = budget_enabled;
    }
    void set_helpers(const HelperTable& h) { helpers_ = &h; }
};

#endif // JIT_BASE_EMITTER_H
