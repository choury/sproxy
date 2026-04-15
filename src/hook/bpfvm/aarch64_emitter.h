//
// aarch64_emitter.h — AArch64-specific JIT code emitter.
//
// ═══════════════════════════════════════════════════════════════════
// AArch64 寄存器分配方案
// ═══════════════════════════════════════════════════════════════════
//
// 所有 11 个 BPF 寄存器都映射到 AArch64 物理寄存器，消除纯计算
// 路径上的内存访问。BPF callee-saved 对齐 AArch64 callee-saved，
// 使它们在调用 helper 函数时自动存活。
//
//   AArch64 Reg │ BPF   │ AAPCS64 类型   │ 用途
//  ─────────────┼───────┼────────────────┼─────────────────────────
//   X9          │ r0    │ caller-saved   │ 返回值 / 累加器
//   X10         │ r1    │ caller-saved   │ 参数寄存器
//   X11         │ r2    │ caller-saved   │ 参数寄存器
//   X12         │ r3    │ caller-saved   │ 参数寄存器
//   X13         │ r4    │ caller-saved   │ 参数寄存器
//   X14         │ r5    │ caller-saved   │ 参数寄存器（最低使用频率）
//   X19         │ r6    │ callee-saved   │ BPF callee-saved
//   X20         │ r7    │ callee-saved   │ BPF callee-saved
//   X21         │ r8    │ callee-saved   │ BPF callee-saved
//   X22         │ r9    │ callee-saved   │ BPF callee-saved
//   X23         │ r10   │ callee-saved   │ 只读帧指针（永远不写回）
//  ─────────────┼───────┼────────────────┼─────────────────────────
//   X28         │ —     │ 固定           │ vm* 指针
//   X0-X2       │ —     │ scratch        │ helper 调用参数
//   X15         │ —     │ scratch        │ TLB 索引 / helper 跳板
//   SP          │ —     │ 固定           │ 硬件栈指针
//   LR (X30)    │ —     │ 固定           │ 返回地址
//
// ═══════════════════════════════════════════════════════════════════

#ifndef AARCH64_EMITTER_H
#define AARCH64_EMITTER_H

#include "jit_base_emitter.h"
#include "jit.h"

#if defined(__aarch64__)

struct bpf_insn;

// ---------------------------------------------------------------------------
// AArch64 register encoding
// ---------------------------------------------------------------------------
namespace ARM {
    constexpr uint8_t X0  = 0;
    constexpr uint8_t X1  = 1;
    constexpr uint8_t X2  = 2;
    constexpr uint8_t X3  = 3;
    constexpr uint8_t X4  = 4;
    constexpr uint8_t X5  = 5;
    constexpr uint8_t X6  = 6;
    constexpr uint8_t X7  = 7;
    constexpr uint8_t X8  = 8;
    constexpr uint8_t X9  = 9;
    constexpr uint8_t X10 = 10;
    constexpr uint8_t X11 = 11;
    constexpr uint8_t X12 = 12;
    constexpr uint8_t X13 = 13;
    constexpr uint8_t X14 = 14;
    constexpr uint8_t X15 = 15;
    constexpr uint8_t X16 = 16;
    constexpr uint8_t X17 = 17;
    constexpr uint8_t X18 = 18;
    constexpr uint8_t X19 = 19;
    constexpr uint8_t X20 = 20;
    constexpr uint8_t X21 = 21;
    constexpr uint8_t X22 = 22;
    constexpr uint8_t X23 = 23;
    constexpr uint8_t X24 = 24;
    constexpr uint8_t X25 = 25;
    constexpr uint8_t X26 = 26;
    constexpr uint8_t X27 = 27;
    constexpr uint8_t X28 = 28;
    constexpr uint8_t FP  = 29;   // X29 = Frame Pointer
    constexpr uint8_t LR  = 30;   // X30 = Link Register
    constexpr uint8_t SP  = 31;   // SP or ZR depending on context
}

// BPF register → AArch64 register mapping
constexpr uint8_t BPF_REG_MAP[11] = {
    ARM::X9,  ARM::X10, ARM::X11, ARM::X12, ARM::X13, ARM::X14,
    ARM::X19, ARM::X20, ARM::X21, ARM::X22, ARM::X23,
};

// Caller-saved BPF registers: r0-r5
constexpr int BPF_CALLER_SAVED_COUNT = 6;
constexpr uint8_t BPF_CALLER_SAVED_ARM[BPF_CALLER_SAVED_COUNT] = {
    ARM::X9, ARM::X10, ARM::X11, ARM::X12, ARM::X13, ARM::X14,
};

// ---------------------------------------------------------------------------
// AArch64Emitter: full AArch64 JIT backend
// ---------------------------------------------------------------------------
class AArch64Emitter : public EmitterBase {
public:
    // --- High-level BPF instruction emission ---

    size_t emit_prologue();
    void emit_safepoint(uint32_t loop_body_size);

    bool emit_alu(const bpf_insn* insn, bool is_64);
    bool emit_ld(const bpf_insn* insn);
    bool emit_ldx(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_st(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
    bool emit_stx_atomic(const bpf_insn* insn, std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    bool emit_jmp(const bpf_insn* insn, int current_index, bool is_64,
                  std::vector<JumpPlaceholder>& placeholders);
    void emit_ja(const bpf_insn* insn, int current_index,
                 std::vector<JumpPlaceholder>& placeholders);
    void emit_ja32(const bpf_insn* insn, int current_index,
                   std::vector<JumpPlaceholder>& placeholders);

    void emit_call_syscall(const bpf_insn* insn, int current_index,
                           const bpf_insn* entry_pc);
    void emit_call_bpf(const bpf_insn* insn, int current_index,
                       uint64_t ret_gpa, const bpf_insn* entry_pc);
    void emit_call_indirect(const bpf_insn* insn, uint64_t ret_gpa);
    void emit_exit();

    // --- Patching (AArch64-specific: B.cond imm19, B imm26) ---
    void patch_branch_cond(size_t inst_offset, size_t target_offset);
    void patch_branch_uncond(size_t inst_offset, size_t target_offset);

private:
    // --- Low-level instruction emission ---
    void emit_insn(uint32_t insn);

    // MOV immediate
    void movz(uint8_t dst, uint16_t imm, int shift, bool is_64 = true);
    void movk(uint8_t dst, uint16_t imm, int shift, bool is_64 = true);
    void mov_imm(uint8_t dst, uint64_t val, bool is_64 = true);

    // Register-to-register
    void mov_reg(uint8_t dst, uint8_t src, bool is_64 = true);

    // ALU reg,reg
    void add_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void sub_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void and_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void orr_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void eor_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void mul_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void msub_reg(uint8_t dst, uint8_t src1, uint8_t src2, uint8_t acc, bool is_64 = true);
    void sdiv_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void udiv_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void neg_reg(uint8_t dst, uint8_t src, bool is_64 = true);
    void lsl_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void lsr_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);
    void asr_reg(uint8_t dst, uint8_t src1, uint8_t src2, bool is_64 = true);

    // ALU reg,imm
    void add_imm(uint8_t dst, uint8_t src, int64_t imm, bool is_64 = true);
    void sub_imm(uint8_t dst, uint8_t src, int64_t imm, bool is_64 = true);
    void and_imm(uint8_t dst, uint8_t src, uint64_t imm, bool is_64 = true);
    void orr_imm(uint8_t dst, uint8_t src, uint64_t imm, bool is_64 = true);
    void eor_imm(uint8_t dst, uint8_t src, uint64_t imm, bool is_64 = true);

    // Shift imm
    void lsl_imm(uint8_t dst, uint8_t src, uint8_t count, bool is_64 = true);
    void lsr_imm(uint8_t dst, uint8_t src, uint8_t count, bool is_64 = true);
    void asr_imm(uint8_t dst, uint8_t src, uint8_t count, bool is_64 = true);

    // Compare / Test
    void cmp_reg(uint8_t src1, uint8_t src2, bool is_64 = true);
    void cmp_imm(uint8_t src, int64_t imm, bool is_64 = true);
    void tst_reg(uint8_t src1, uint8_t src2, bool is_64 = true);

    // Branch
    void b_cond(uint8_t cond);   // B.cond (placeholder, 4 bytes)
    void b_uncond();             // B (placeholder, 4 bytes)
    void blr(uint8_t reg);
    void ret();

    // Load/Store
    void ldr_imm(uint8_t dst, uint8_t base, int32_t offset, bool is_64 = true);
    void str_imm(uint8_t src, uint8_t base, int32_t offset, bool is_64 = true);
    void ldrsw(uint8_t dst, uint8_t base, int32_t offset);  // LDR W signed word→X
    void ldrsh(uint8_t dst, uint8_t base, int32_t offset, bool is_64 = true);
    void ldrsb(uint8_t dst, uint8_t base, int32_t offset, bool is_64 = true);
    void ldrh(uint8_t dst, uint8_t base, int32_t offset);
    void ldrb(uint8_t dst, uint8_t base, int32_t offset);
    void strh(uint8_t src, uint8_t base, int32_t offset);
    void strb(uint8_t src, uint8_t base, int32_t offset);
    void stp(uint8_t r1, uint8_t r2, uint8_t base, int32_t offset, bool is_64 = true);
    void ldp(uint8_t r1, uint8_t r2, uint8_t base, int32_t offset, bool is_64 = true);

    // Sign extension
    void sxtb(uint8_t dst, uint8_t src, bool is_64 = true);
    void sxth(uint8_t dst, uint8_t src, bool is_64 = true);
    void sxtw(uint8_t dst, uint8_t src);

    // Byte swap
    void rev16(uint8_t dst, uint8_t src, bool is_64 = true);
    void rev32(uint8_t dst, uint8_t src);
    void rev64(uint8_t dst, uint8_t src);

    // Compare-and-branch
    void cbz(uint8_t reg, bool is_64 = true);  // placeholder
    void cbnz(uint8_t reg, bool is_64 = true); // placeholder

    // Memory barrier
    void dmb();

    // --- BPF register access ---
    void load_bpf(uint8_t bpf_reg, uint8_t dst);
    void store_bpf(uint8_t bpf_reg, uint8_t src, bool is_64);

    // --- Register flush/reload ---
    void flush_to_vm();
    void reload_from_vm();
    void reload_caller_saved();
    void spill_caller_saved();
    void restore_caller_saved();

    // --- Helper call ---
    void call_helper(void* addr);

    // --- TLB inline ---
    MemAccessContext begin_mem_access(uint8_t base_reg, int16_t offset,
                                      int access_size, bool is_write);
    void finish_mem_access(MemAccessContext& ctx,
                           std::vector<AbortPatchInfo>& abort_patches, int bpf_index);
};

// AArch64 condition codes
namespace ARMCond {
    constexpr uint8_t EQ = 0;  // Equal / Zero
    constexpr uint8_t NE = 1;  // Not Equal / Not Zero
    constexpr uint8_t CS = 2;  // Carry Set (unsigned >=)
    constexpr uint8_t CC = 3;  // Carry Clear (unsigned <)
    constexpr uint8_t MI = 4;  // Negative
    constexpr uint8_t PL = 5;  // Positive or Zero
    constexpr uint8_t VS = 6;  // Overflow
    constexpr uint8_t VC = 7;  // No Overflow
    constexpr uint8_t HI = 8;  // Unsigned Higher
    constexpr uint8_t LS = 9;  // Unsigned Lower or Same
    constexpr uint8_t GE = 10; // Signed >=
    constexpr uint8_t LT = 11; // Signed <
    constexpr uint8_t GT = 12; // Signed >
    constexpr uint8_t LE = 13; // Signed <=
    constexpr uint8_t AL = 14; // Always
}

#endif // __aarch64__

#endif // AARCH64_EMITTER_H
