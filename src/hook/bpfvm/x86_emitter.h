//
// x86_emitter.h — x86_64-specific JIT code emitter.
//
// ═══════════════════════════════════════════════════════════════════
// x86_64 寄存器分配方案
// ═══════════════════════════════════════════════════════════════════
//
// 所有 11 个 BPF 寄存器都映射到 x86 物理寄存器，消除纯计算路径上的
// 内存访问。BPF callee-saved 寄存器对齐 x86 callee-saved 寄存器，
// 使它们在调用 helper 函数时自动存活。
//
//   x86 寄存器 │ BPF   │ ABI 类型       │ 用途
//  ────────────┼───────┼────────────────┼─────────────────────────
//   R8         │ r0    │ caller-saved   │ 返回值 / 累加器
//   R9         │ r1    │ caller-saved   │ 常用基址寄存器
//   R10        │ r2    │ caller-saved   │ 参数寄存器
//   RDI        │ r3    │ caller-saved   │ 参数寄存器
//   RSI        │ r4    │ caller-saved   │ 参数寄存器
//   RDX        │ r5    │ caller-saved   │ 参数寄存器（最低使用频率）
//   RBX        │ r6    │ callee-saved   │ BPF callee-saved
//   R12        │ r7    │ callee-saved   │ BPF callee-saved
//   R13        │ r8    │ callee-saved   │ BPF callee-saved
//   R14        │ r9    │ callee-saved   │ BPF callee-saved
//   R15        │ r10   │ callee-saved   │ 只读帧指针（永远不写回）
//  ────────────┼───────┼────────────────┼─────────────────────────
//   RAX        │ —     │ scratch        │ TLB 地址 / 返回值 / 立即数
//   RCX        │ —     │ scratch        │ 移位计数 (CL)
//   R11        │ —     │ scratch        │ TLB SIB 索引
//   RBP        │ —     │ 固定           │ vm* 指针 ([rbp+disp] 寻址)
//   RSP        │ —     │ 固定           │ 硬件栈指针
//
// Helper 调用策略：
//   - TLB miss 慢速路径：push/pop 6 个 caller-saved（callee-saved 自动存活）
//   - Safepoint：flush_to_vm + call + reload_caller_saved
//   - Syscall：flush_to_vm + call + reload_from_vm（syscall 可能改任意寄存器）
//   - BPF CALL / EXIT：flush_to_vm + jmp vm_exit（重新进入 JIT 循环）
//
// ═══════════════════════════════════════════════════════════════════

#ifndef X86_EMITTER_H
#define X86_EMITTER_H

#include "jit_base_emitter.h"
#include "jit.h"

#if defined(__x86_64__)

struct bpf_insn;

// ---------------------------------------------------------------------------
// x86_64 register encoding (ModRM rm/reg field values)
// ---------------------------------------------------------------------------
namespace X86 {
    constexpr uint8_t RAX = 0;
    constexpr uint8_t RCX = 1;
    constexpr uint8_t RDX = 2;
    constexpr uint8_t RBX = 3;
    constexpr uint8_t RSP = 4;
    constexpr uint8_t RBP = 5;
    constexpr uint8_t RSI = 6;
    constexpr uint8_t RDI = 7;
    constexpr uint8_t R8  = 8;
    constexpr uint8_t R9  = 9;
    constexpr uint8_t R10 = 10;
    constexpr uint8_t R11 = 11;
    constexpr uint8_t R12 = 12;
    constexpr uint8_t R13 = 13;
    constexpr uint8_t R14 = 14;
    constexpr uint8_t R15 = 15;
}

// BPF register → x86 register mapping (all 11 BPF registers)
//   r0=R8, r1=R9, r2=R10, r3=RDI, r4=RSI, r5=RDX,
//   r6=RBX, r7=R12, r8=R13, r9=R14, r10=R15
constexpr uint8_t BPF_REG_MAP[11] = {
    X86::R8,  X86::R9,  X86::R10, X86::RDI, X86::RSI, X86::RDX,
    X86::RBX, X86::R12, X86::R13, X86::R14, X86::R15,
};

// Caller-saved BPF registers: r0-r5 (mapped to R8, R9, R10, RDI, RSI, RDX)
// These must be saved/restored around helper calls.
constexpr int BPF_CALLER_SAVED_COUNT = 6;
constexpr uint8_t BPF_CALLER_SAVED_X86[BPF_CALLER_SAVED_COUNT] = {
    X86::R8, X86::R9, X86::R10, X86::RDI, X86::RSI, X86::RDX,
};

// ---------------------------------------------------------------------------
// X86Emitter: full x86_64 JIT backend
// ---------------------------------------------------------------------------
class X86Emitter : public EmitterBase {
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

    MemAccessContext begin_mem_access(uint8_t base_x86_reg, int16_t offset,
                                      int access_size, bool is_write);
    void finish_mem_access(MemAccessContext& ctx,
                           std::vector<AbortPatchInfo>& abort_patches, int bpf_index);

    // --- Patching (x86-specific: Jcc rel32, JMP rel32) ---
    void patch_branch_cond(size_t inst_offset, size_t target_offset);
    void patch_branch_uncond(size_t inst_offset, size_t target_offset);

private:

    // --- ModRM ---
    static uint8_t modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
        return (mod << 6) | ((reg & 7) << 3) | (rm & 7);
    }

    // --- REX byte construction ---
    // W=64-bit operand, R=reg extension, X=index extension, B=rm/base extension
    static uint8_t rex(bool w, bool r, bool x, bool b) {
        return 0x40 | (w ? 8 : 0) | (r ? 4 : 0) | (x ? 2 : 0) | (b ? 1 : 0);
    }

    // --- Memory access (frame-relative: [RBP + disp32]) ---
    void load_r64(uint8_t dst, int32_t disp);
    void store_r64(int32_t disp, uint8_t src);

    // --- SIB-addressed operations: [RBP + R11 + disp32] ---
    //     R11 用作 TLB 索引寄存器（scratch 寄存器）
    void sib_op_rax(uint8_t opcode, int32_t disp);
    void sib_test_dword(int32_t disp, uint32_t imm);
    void sib_cmp_byte(int32_t disp, uint8_t imm);

    // --- BPF register access ---
    //     所有 BPF 寄存器都在 x86 物理寄存器中，load/store 只做 reg-to-reg mov
    void load_bpf(uint8_t bpf_reg, uint8_t x86_dst);
    void store_bpf(uint8_t bpf_reg, uint8_t x86_src, bool is_64);

    // --- Register flush/reload for helper calls ---
    //     flush: 写回 vm->reg[]  reload: 从 vm->reg[] 加载
    void flush_to_vm();           // 写回全部 10 个可写 BPF 寄存器
    void reload_from_vm();        // 加载全部 10 个可写 BPF 寄存器
    void reload_caller_saved();   // 只加载 r0-r5
    void spill_caller_saved();    // push r0-r5 到 x86 栈（TLB miss 快速保存）
    void restore_caller_saved();  // pop 恢复 r0-r5（反向顺序）

    // --- Inline DIV/MOD ---
    void emit_inline_div(bool is_64, bool is_unsigned, bool is_mod);

    // --- Register-to-register ---
    void mov_r64(uint8_t dst, uint8_t src);
    void mov_r32(uint8_t dst, uint8_t src);  // 32-bit mov (zero-extends to 64)

    // --- ALU64 reg,reg ---
    void add64();    void sub64();    void or64();     void and64();
    void xor64();    void mul64();    void neg64();
    void shl64_cl(); void shr64_cl(); void sar64_cl();

    // --- ALU64 reg,imm32 ---
    void add64_imm(int32_t imm);  void sub64_imm(int32_t imm);
    void or64_imm(int32_t imm);   void and64_imm(int32_t imm);
    void xor64_imm(int32_t imm);  void mul64_imm(int32_t imm);
    void shl64_imm(uint8_t count); void shr64_imm(uint8_t count);
    void sar64_imm(uint8_t count);

    // --- ALU32 reg,reg ---
    void add32();    void sub32();    void or32();     void and32();
    void xor32();    void mul32();    void neg32();
    void shl32_cl(); void shr32_cl(); void sar32_cl();

    // --- ALU32 reg,imm32 ---
    void add32_imm(int32_t imm);  void sub32_imm(int32_t imm);
    void or32_imm(int32_t imm);   void and32_imm(int32_t imm);
    void xor32_imm(int32_t imm);  void mul32_imm(int32_t imm);
    void shl32_imm(uint8_t count); void shr32_imm(uint8_t count);
    void sar32_imm(uint8_t count);

    // --- CMP / TEST ---
    void cmp64();          void cmp64_imm(int32_t imm);
    void cmp32();          void cmp32_imm(int32_t imm);
    void test64();         void test64_imm(int32_t imm);
    void test32();         void test32_imm(int32_t imm);

    // --- Control flow ---
    void jcc_rel32(uint8_t cc);
    void jmp_rel32();

    // --- Immediate / common patterns ---
    void mov_rax_imm64(uint64_t val);
    void store_imm64(int32_t disp, int32_t imm);
    void store_imm32_zext(int32_t disp, int32_t imm);
    void call_helper(void* addr);
    void test_rax_rax();   void test_eax_eax();  void test_al_al();

    // --- Prologue/epilogue helpers ---
    void push_rbp();       void pop_rbp();
    void push_reg(uint8_t r);
    void pop_reg(uint8_t r);

    // --- Internal emit helpers ---
    void emit_helper_call(void* helper);
};

#endif // __x86_64__

#endif // X86_EMITTER_H
