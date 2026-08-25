//
// x86_emitter.cpp — x86_64-specific JIT code emission implementation.
//
// 寄存器分配方案详见 x86_emitter.h 顶部注释。
// 核心思路：全部 11 个 BPF 寄存器都映射到 x86 物理寄存器，
// ALU/分支指令在纯寄存器之间操作，只在调用 helper 函数时
// 才与 vm->reg[] 内存交互。
//

#include "x86_emitter.h"
#include "../../include/bpf_fp.h"

#include <cstdint>
#include <cstring>

#if defined(__x86_64__)

#include "../insn.h"

// ---------------------------------------------------------------------------
// Patching: Jcc rel32 (6 bytes, disp at +2) and JMP rel32 (5 bytes, disp at +1)
// ---------------------------------------------------------------------------

void X86Emitter::patch_branch_cond(size_t off, size_t target) {
    uint32_t rel = (uint32_t)(target - (off + 6));
    memcpy(data() + off + 2, &rel, 4);
}
void X86Emitter::patch_branch_uncond(size_t off, size_t target) {
    uint32_t rel = (uint32_t)(target - (off + 5));
    memcpy(data() + off + 1, &rel, 4);
}

// ---------------------------------------------------------------------------
// Low-level x86_64 emission: memory access [RBP + disp32]
// ---------------------------------------------------------------------------

void X86Emitter::load_r64(uint8_t dst, int32_t disp) {
    // mov dst, [rbp + disp32]
    uint8_t r = rex(true, dst >= 8, false, false);
    emit8(r);
    emit8(0x8B);
    emit8(modrm(2, dst & 7, X86::RBP));
    emit32(disp);
}

void X86Emitter::store_r64(int32_t disp, uint8_t src) {
    // mov [rbp + disp32], src
    uint8_t r = rex(true, src >= 8, false, false);
    emit8(r);
    emit8(0x89);
    emit8(modrm(2, src & 7, X86::RBP));
    emit32(disp);
}

// ---------------------------------------------------------------------------
// SIB-addressed operations: [RBP + R11 + disp32]
// R11 用作 TLB 索引寄存器（scratch 寄存器，替代旧方案中的 RDI）
//
// SIB 编码：
//   ModRM = mod:10 reg:xxx rm:100 (SIB follows)
//   SIB   = scale:00 index:R11(011) base:RBP(101)
//   R11 >= 8，所以需要 REX.X 位
// ---------------------------------------------------------------------------

void X86Emitter::sib_op_rax(uint8_t opcode, int32_t disp) {
    // op rax, [rbp + r11 + disp32]
    // REX.W=1, REX.X=1 (R11 index): 0x4A
    emit8(0x4A); emit8(opcode);
    emit8(0x84);  // ModRM: mod=10, reg=RAX(0), rm=100(SIB)
    emit8(0x1D);  // SIB: scale=00, index=R11(011), base=RBP(101)
    emit32(disp);
}

void X86Emitter::sib_test_dword(int32_t disp, uint32_t imm) {
    // test dword [rbp + r11 + disp32], imm32
    // REX.X=1 for R11: 0x42
    emit8(0x42);
    emit8(0xF7);
    emit8(0x84);  // ModRM: mod=10, reg=0(test), rm=100(SIB)
    emit8(0x1D);  // SIB: scale=00, index=R11(011), base=RBP(101)
    emit32(disp);
    emit32(imm);
}

void X86Emitter::sib_cmp_byte(int32_t disp, uint8_t imm) {
    // cmp byte [rbp + r11 + disp32], imm8
    emit8(0x42);
    emit8(0x80);
    emit8(0xBC);  // ModRM: mod=10, reg=7(cmp), rm=100(SIB)
    emit8(0x1D);  // SIB: scale=00, index=R11(011), base=RBP(101)
    emit32(disp);
    emit8(imm);
}

// ---------------------------------------------------------------------------
// BPF register access — 全部 BPF 寄存器都在 x86 物理寄存器中
// ---------------------------------------------------------------------------

void X86Emitter::load_bpf(uint8_t bpf_reg, uint8_t x86_dst) {
    uint8_t mapped = BPF_REG_MAP[bpf_reg];
    if (mapped != x86_dst) {
        mov_r64(x86_dst, mapped);
    }
}

void X86Emitter::store_bpf(uint8_t bpf_reg, uint8_t x86_src, bool is_64) {
    uint8_t mapped = BPF_REG_MAP[bpf_reg];
    if (!is_64) {
        // 32 位结果需要零扩展到 64 位：mov r32, r32
        mov_r32(x86_src, x86_src);
    }
    if (mapped != x86_src) {
        mov_r64(mapped, x86_src);
    }
}

// ---------------------------------------------------------------------------
// Register flush/reload — 与 vm->reg[] 内存交互
// ---------------------------------------------------------------------------

void X86Emitter::flush_to_vm() {
    // 写回全部 10 个可写 BPF 寄存器到 vm->reg[]（r10 只读，不写回）
    for (int i = 0; i < 10; i++) {
        store_r64((int32_t)(off_reg_ + i * 8), BPF_REG_MAP[i]);
    }
}

void X86Emitter::reload_from_vm() {
    // 从 vm->reg[] 加载全部 10 个可写 BPF 寄存器
    for (int i = 0; i < 10; i++) {
        load_r64(BPF_REG_MAP[i], (int32_t)(off_reg_ + i * 8));
    }
}

void X86Emitter::reload_caller_saved() {
    // 只加载 r0-r5（callee-saved 的 r6-r9 在 CALL 后自动存活）
    for (int i = 0; i < BPF_CALLER_SAVED_COUNT; i++) {
        load_r64(BPF_CALLER_SAVED_X86[i], (int32_t)(off_reg_ + i * 8));
    }
}

void X86Emitter::spill_caller_saved() {
    // push r0-r5 的 x86 寄存器到栈（TLB miss 慢速路径用）
    for (int i = 0; i < BPF_CALLER_SAVED_COUNT; i++) {
        push_reg(BPF_CALLER_SAVED_X86[i]);
    }
}

void X86Emitter::restore_caller_saved() {
    // pop 恢复 r0-r5（反向顺序）
    for (int i = BPF_CALLER_SAVED_COUNT - 1; i >= 0; i--) {
        pop_reg(BPF_CALLER_SAVED_X86[i]);
    }
}

// ---------------------------------------------------------------------------
// Register-to-register MOV
// ---------------------------------------------------------------------------

void X86Emitter::mov_r64(uint8_t dst, uint8_t src) {
    // mov dst, src (64-bit)
    uint8_t r = rex(true, src >= 8, false, dst >= 8);
    emit8(r);
    emit8(0x89);
    emit8(modrm(3, src & 7, dst & 7));
}

void X86Emitter::mov_r32(uint8_t dst, uint8_t src) {
    // mov r32, r32 (zero-extends to 64-bit)
    // 需要 REX 前缀仅当使用了 R8-R15
    if (src >= 8 || dst >= 8) {
        uint8_t r = rex(false, src >= 8, false, dst >= 8);
        emit8(r);
    }
    emit8(0x89);
    emit8(modrm(3, src & 7, dst & 7));
}

// --- ALU64 reg,reg (operate on RAX with RCX as source) ---

void X86Emitter::add64()  { emit8(0x48); emit8(0x01); emit8(0xC8); }
void X86Emitter::sub64()  { emit8(0x48); emit8(0x29); emit8(0xC8); }
void X86Emitter::or64()   { emit8(0x48); emit8(0x09); emit8(0xC8); }
void X86Emitter::and64()  { emit8(0x48); emit8(0x21); emit8(0xC8); }
void X86Emitter::xor64()  { emit8(0x48); emit8(0x31); emit8(0xC8); }
void X86Emitter::mul64()  { emit8(0x48); emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void X86Emitter::neg64()  { emit8(0x48); emit8(0xF7); emit8(0xD8); }

void X86Emitter::shl64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE0); }
void X86Emitter::shr64_cl() { emit8(0x48); emit8(0xD3); emit8(0xE8); }
void X86Emitter::sar64_cl() { emit8(0x48); emit8(0xD3); emit8(0xF8); }

// --- ALU64 reg,imm32 (operate on RAX) ---

void X86Emitter::add64_imm(int32_t imm)  { emit8(0x48); emit8(0x05); emit32(imm); }
void X86Emitter::sub64_imm(int32_t imm)  { emit8(0x48); emit8(0x2D); emit32(imm); }
void X86Emitter::or64_imm(int32_t imm)   { emit8(0x48); emit8(0x0D); emit32(imm); }
void X86Emitter::and64_imm(int32_t imm)  { emit8(0x48); emit8(0x25); emit32(imm); }
void X86Emitter::xor64_imm(int32_t imm)  { emit8(0x48); emit8(0x35); emit32(imm); }

void X86Emitter::shl64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE0); emit8(c); }
void X86Emitter::shr64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xE8); emit8(c); }
void X86Emitter::sar64_imm(uint8_t c) { emit8(0x48); emit8(0xC1); emit8(0xF8); emit8(c); }

void X86Emitter::mul64_imm(int32_t imm) { emit8(0x48); emit8(0x69); emit8(0xC0); emit32(imm); }

// --- ALU32 reg,reg ---

void X86Emitter::add32()  { emit8(0x01); emit8(0xC8); }
void X86Emitter::sub32()  { emit8(0x29); emit8(0xC8); }
void X86Emitter::or32()   { emit8(0x09); emit8(0xC8); }
void X86Emitter::and32()  { emit8(0x21); emit8(0xC8); }
void X86Emitter::xor32()  { emit8(0x31); emit8(0xC8); }
void X86Emitter::mul32()  { emit8(0x0F); emit8(0xAF); emit8(0xC1); }
void X86Emitter::neg32()  { emit8(0xF7); emit8(0xD8); }

void X86Emitter::shl32_cl() { emit8(0xD3); emit8(0xE0); }
void X86Emitter::shr32_cl() { emit8(0xD3); emit8(0xE8); }
void X86Emitter::sar32_cl() { emit8(0xD3); emit8(0xF8); }

// --- ALU32 reg,imm32 ---

void X86Emitter::add32_imm(int32_t imm)  { emit8(0x05); emit32(imm); }
void X86Emitter::sub32_imm(int32_t imm)  { emit8(0x2D); emit32(imm); }
void X86Emitter::or32_imm(int32_t imm)   { emit8(0x0D); emit32(imm); }
void X86Emitter::and32_imm(int32_t imm)  { emit8(0x25); emit32(imm); }
void X86Emitter::xor32_imm(int32_t imm)  { emit8(0x35); emit32(imm); }

void X86Emitter::shl32_imm(uint8_t c) { emit8(0xC1); emit8(0xE0); emit8(c); }
void X86Emitter::shr32_imm(uint8_t c) { emit8(0xC1); emit8(0xE8); emit8(c); }
void X86Emitter::sar32_imm(uint8_t c) { emit8(0xC1); emit8(0xF8); emit8(c); }

void X86Emitter::mul32_imm(int32_t imm) { emit8(0x69); emit8(0xC0); emit32(imm); }

// --- CMP / TEST (RAX vs RCX or immediate) ---

void X86Emitter::cmp64()          { emit8(0x48); emit8(0x39); emit8(0xC8); }
void X86Emitter::cmp64_imm(int32_t imm) { emit8(0x48); emit8(0x3D); emit32(imm); }
void X86Emitter::cmp32()          { emit8(0x39); emit8(0xC8); }
void X86Emitter::cmp32_imm(int32_t imm) { emit8(0x3D); emit32(imm); }
void X86Emitter::test64()         { emit8(0x48); emit8(0x85); emit8(0xC8); }
void X86Emitter::test64_imm(int32_t imm) { emit8(0x48); emit8(0xA9); emit32(imm); }
void X86Emitter::test32()         { emit8(0x85); emit8(0xC8); }
void X86Emitter::test32_imm(int32_t imm) { emit8(0xA9); emit32(imm); }

// --- Control flow ---

void X86Emitter::jcc_rel32(uint8_t cc) { emit8(0x0F); emit8(cc); emit32(0); }
void X86Emitter::jmp_rel32() { emit8(0xE9); emit32(0); }

// --- Immediate / common patterns ---

void X86Emitter::mov_rax_imm64(uint64_t val) {
    emit8(0x48); emit8(0xB8); emit64(val);
}

void X86Emitter::store_imm64(int32_t disp, int32_t imm) {
    // mov qword [rbp + disp32], imm32 (sign-extended)
    emit8(0x48); emit8(0xC7); emit8(modrm(2, 0, X86::RBP));
    emit32(disp); emit32(imm);
}

void X86Emitter::store_imm32_zext(int32_t disp, int32_t imm) {
    if (imm >= 0) {
        store_imm64(disp, imm);
    } else {
        // 负的 imm32 不能用 sign-extended store（结果是负数），
        // 先 mov eax, imm32（零扩展），再 store
        emit8(0xB8); emit32(imm);
        store_r64(disp, X86::RAX);
    }
}

void X86Emitter::call_helper(void* addr) {
    // mov r11, imm64; call r11
    // 使用 R11 作为间接调用跳板（R11 是 scratch 寄存器）
    emit8(0x49); emit8(0xBB); emit64((uint64_t)(uintptr_t)addr);
    emit8(0x41); emit8(0xFF); emit8(0xD3);  // call r11
}

void X86Emitter::test_rax_rax() { emit8(0x48); emit8(0x85); emit8(0xC0); }
void X86Emitter::test_eax_eax() { emit8(0x85); emit8(0xC0); }
void X86Emitter::test_al_al()   { emit8(0x84); emit8(0xC0); }

// --- Prologue/epilogue helpers ---

void X86Emitter::push_rbp() { emit8(0x55); }
void X86Emitter::pop_rbp()  { emit8(0x5D); }

void X86Emitter::push_reg(uint8_t r) {
    if (r >= 8) emit8(0x41);
    emit8(0x50 + (r & 7));
}

void X86Emitter::pop_reg(uint8_t r) {
    if (r >= 8) emit8(0x41);
    emit8(0x58 + (r & 7));
}

// ---------------------------------------------------------------------------
// Helper call (div/mod): 将 RAX/RCX 映射到 System V ABI 参数位置
// ---------------------------------------------------------------------------

void X86Emitter::emit_helper_call(void* helper) {
    // 入口假设：RAX=被除数, RCX=除数, EDX=off (已由调用方设置)
    // System V ABI: RDI=arg1, RSI=arg2, RDX=arg3
    // 但 RDI=BPF r3, RSI=BPF r4 — 调用 helper 前必须已 spill
    emit8(0x48); emit8(0x89); emit8(0xC7);  // mov rdi, rax
    emit8(0x48); emit8(0x89); emit8(0xCE);  // mov rsi, rcx
    call_helper(helper);
}

// ---------------------------------------------------------------------------
// SSE2/SSE 浮点原语（供 emit_call_softfp 使用）。
// 这些原语在 xmm 寄存器上操作（与整数 REX 扩展约定一致：reg 字段用 R 位扩展，
// rm 字段用 B 位扩展）。浮点位模式在整数寄存器(r1/r2 -> R9/R10)与 xmm 之间用 movq/movd 搬运。
// ---------------------------------------------------------------------------

// movq xmm, r64  ——  REX.W 66 0F 6E /r   (xmm = 位模式(r64))
void X86Emitter::sse_movq_xmm_r64(uint8_t xmm, uint8_t r64) {
    // mandatory 66, REX.W(=1), reg=xmm(R), rm=r64(B)
    emit8(0x66);
    emit8(rex(true, xmm >= 8, false, r64 >= 8));
    emit8(0x0F); emit8(0x6E);
    emit8(modrm(3, xmm & 7, r64 & 7));
}

// movq r64, xmm  ——  REX.W 66 0F 7E /r   (r64 = 位模式(xmm))
void X86Emitter::sse_movq_r64_xmm(uint8_t r64, uint8_t xmm) {
    emit8(0x66);
    emit8(rex(true, xmm >= 8, false, r64 >= 8));
    emit8(0x0F); emit8(0x7E);
    emit8(modrm(3, xmm & 7, r64 & 7));
}

// movd xmm, r32  ——  66 0F 6E /r   (xmm[0:31] = r32，高位清零)
void X86Emitter::sse_movd_xmm_r32(uint8_t xmm, uint8_t r32) {
    emit8(0x66);
    emit8(rex(false, xmm >= 8, false, r32 >= 8));
    emit8(0x0F); emit8(0x6E);
    emit8(modrm(3, xmm & 7, r32 & 7));
}

// movd r32, xmm  ——  66 0F 7E /r   (r32 = xmm[0:31])
void X86Emitter::sse_movd_r32_xmm(uint8_t r32, uint8_t xmm) {
    emit8(0x66);
    emit8(rex(false, xmm >= 8, false, r32 >= 8));
    emit8(0x0F); emit8(0x7E);
    emit8(modrm(3, xmm & 7, r32 & 7));
}

// 标量算术：dst (op)= src
//   prefix=0xF2 -> 标量双精度 (addsd/subsd/mulsd/divsd)
//   prefix=0xF3 -> 标量单精度 (addss/subss/mulss/divss)
//   SSE `XX /r` 中 ModRM 的 **reg 字段 = dst，rm 字段 = src**
//   （addsd xmm_dst, xmm_src）。REX：R 位扩展 dst(reg)，B 位扩展 src(rm)。
void X86Emitter::sse_alu_scalar(uint8_t prefix, uint8_t op, uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(prefix);
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(op);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// sqrtsd/sqrtss xmm_dst, xmm_src  ——  prefix 0F 51 /r   (reg=dst, rm=src)
void X86Emitter::sse_sqrt_scalar(uint8_t prefix, uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(prefix);
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x51);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// xorps xmm_dst, xmm_src —— 0F 57 /r （位异或，用于 neg：翻转符号位）
//   ModRM reg=dst, rm=src（dst ^= src）。REX: R 位扩 dst，B 位扩 src。
void X86Emitter::sse_xorps(uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x57);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// andps xmm_dst, xmm_src —— 0F 54 /r （位与，用于 fabs：清符号位）
//   ModRM reg=dst, rm=src（dst &= src）。REX: R 位扩 dst，B 位扩 src。
void X86Emitter::sse_andps(uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x54);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// orps xmm_dst, xmm_src —— 0F 56 /r （位或，用于 copysign：置符号位）
//   ModRM reg=dst, rm=src（dst |= src）。REX: R 位扩 dst，B 位扩 src。
void X86Emitter::sse_orps(uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x56);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// cvtsi2sd xmm, r/m  —— 有符号整数 -> double
//   64位源: REX.W F2 0F 2A /r    32位源: F2 0F 2A /r
void X86Emitter::sse_cvtsi2sd(uint8_t dst_xmm, uint8_t src_x86, bool is_signed64) {
    emit8(0xF2);
    emit8(rex(is_signed64, dst_xmm >= 8, false, src_x86 >= 8));
    emit8(0x0F); emit8(0x2A);
    emit8(modrm(3, dst_xmm & 7, src_x86 & 7));
}

// cvtsi2ss xmm, r/m  —— 有符号整数 -> float
//   64位源: REX.W F3 0F 2A /r    32位源: F3 0F 2A /r
void X86Emitter::sse_cvtsi2ss(uint8_t dst_xmm, uint8_t src_x86, bool is_signed64) {
    emit8(0xF3);
    emit8(rex(is_signed64, dst_xmm >= 8, false, src_x86 >= 8));
    emit8(0x0F); emit8(0x2A);
    emit8(modrm(3, dst_xmm & 7, src_x86 & 7));
}

// cvttsd2si r64, xmm —— double -> 有符号 64 位整数（向 0 截断）
//   注意是 CVTT（trunc），不是 CVT（按 MXCSR 舍入，默认四舍六入五成双）。
//   C 的 (int)d / do_softfp 的 (int32_t)d 都是向 0 截断，必须用 CVTT。
//   REX.W F2 0F 2C /r   ModRM: reg=dst(r64), rm=src(xmm)
//   r64>=8 -> REX.R；xmm>=8 -> REX.B
void X86Emitter::sse_cvtsd2si(uint8_t dst_x86, uint8_t src_xmm) {
    emit8(0xF2);
    emit8(rex(true, dst_x86 >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x2C);
    emit8(modrm(3, dst_x86 & 7, src_xmm & 7));
}

// cvttss2si r64, xmm —— float -> 有符号 64 位整数（向 0 截断）
//   REX.W F3 0F 2C /r   ModRM: reg=dst(r64), rm=src(xmm)
void X86Emitter::sse_cvtss2si(uint8_t dst_x86, uint8_t src_xmm) {
    emit8(0xF3);
    emit8(rex(true, dst_x86 >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x2C);
    emit8(modrm(3, dst_x86 & 7, src_xmm & 7));
}

// cvtss2sd xmm, xmm —— float -> double   F3 0F 5A /r   (reg=dst, rm=src)
void X86Emitter::sse_cvtss2sd(uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(0xF3);
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x5A);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// cvtsd2ss xmm, xmm —— double -> float   F2 0F 5A /r   (reg=dst, rm=src)
void X86Emitter::sse_cvtsd2ss(uint8_t dst_xmm, uint8_t src_xmm) {
    emit8(0xF2);
    emit8(rex(false, dst_xmm >= 8, false, src_xmm >= 8));
    emit8(0x0F); emit8(0x5A);
    emit8(modrm(3, dst_xmm & 7, src_xmm & 7));
}

// ucomisd xmm_a, xmm_b —— 无序比较设置 EFLAGS。REX.W 66 0F 2E /r  (reg=a, rm=b)
void X86Emitter::sse_ucomisd(uint8_t xmm_a, uint8_t xmm_b) {
    emit8(0x66);
    emit8(rex(true, xmm_a >= 8, false, xmm_b >= 8));
    emit8(0x0F); emit8(0x2E);
    emit8(modrm(3, xmm_a & 7, xmm_b & 7));
}

// ucomiss xmm_a, xmm_b —— 无序比较设置 EFLAGS。66 不要；0F 2E /r  (reg=a, rm=b)
void X86Emitter::sse_ucomiss(uint8_t xmm_a, uint8_t xmm_b) {
    emit8(rex(false, xmm_a >= 8, false, xmm_b >= 8));
    emit8(0x0F); emit8(0x2E);
    emit8(modrm(3, xmm_a & 7, xmm_b & 7));
}

// ---------------------------------------------------------------------------
// Inline DIV/MOD — replace helper call with hardware DIV/IDIV + edge-case checks
//
// 入口假设：RAX = 被除数 (dst), RCX = 除数 (src)
// RDX 映射到 BPF r5，需要保存/恢复。
// DIV/IDIV 使用 RDX:RAX 作为被除数，商在 RAX，余数在 RDX。
// ---------------------------------------------------------------------------
//
// 代码布局：
//   [save RDX]
//   test rcx, rcx; JZ .zero
//   [signed: cmp rcx,-1; JNZ .do_div; cmp rax,INT_MIN; JNE .do_div; JMP .after_div]
//   .do_div:
//   [cqo|xor edx,edx]; [div|idiv] rcx
//   [mod: mov rax, rdx]
//   JMP .after_div
//   .zero:
//   [DIV: xor rax,rax | MOD: leave rax as-is (dst)]
//   .after_div:
//   [restore RDX]
//

void X86Emitter::emit_inline_div(bool is_64, bool is_unsigned, bool is_mod) {
    // 保存 BPF r5 (RDX)：用 push/pop 代替 store/load vm->reg[5]，
    // 栈顶几乎必然在 L1 cache，且各只需 1-2 字节编码。
    push_reg(X86::RDX);

    // 分支布局：热路径（除数非零）fall-through，冷路径（除零/溢出）跳出。
    //
    // test rcx, rcx; JZ .zero
    if (is_64) emit8(0x48);
    emit8(0x85); emit8(0xC9);
    size_t jz_zero = size();
    emit8(0x0F); emit8(0x84); emit32(0);  // JZ .zero (cold)

    if (!is_unsigned) {
        // --- Signed: INT_MIN / -1 overflow check ---
        // 热路径 fall-through 到 .do_div，溢出跳出。

        // cmp rcx/ecx, -1
        if (is_64) {
            emit8(0x48); emit8(0x83); emit8(0xF9); emit8(0xFF);  // cmp rcx, -1
        } else {
            emit8(0x83); emit8(0xF9); emit8(0xFF);  // cmp ecx, -1
        }
        size_t jnz_do_div = size();
        emit8(0x0F); emit8(0x85); emit32(0);  // JNZ .do_div (likely)

        // 除数 == -1，检查被除数 == INT_MIN
        if (is_64) {
            // mov r11, INT64_MIN; cmp rax, r11
            emit8(0x49); emit8(0xBB); emit64(0x8000000000000000ULL);
            emit8(0x4C); emit8(0x39); emit8(0xD8);
        } else {
            // cmp eax, INT32_MIN (sign-extended imm32)
            emit8(0x3D); emit32(0x80000000u);
        }
        size_t jne_do_div = size();
        emit8(0x0F); emit8(0x85); emit32(0);  // JNE .do_div (likely)

        // INT_MIN / -1: DIV 结果 = INT_MIN (已在 RAX), MOD 结果 = 0
        if (is_mod) {
            if (is_64) emit8(0x48);
            emit8(0x31); emit8(0xC0);  // xor eax, eax
        }
        // 跳过实际除法，直接到 .done
        size_t jmp_done = size();
        emit8(0xE9); emit32(0);  // JMP .done (cold)

        // .do_div: 热路径汇合点
        size_t do_div = size();
        patch_branch_cond(jnz_do_div, do_div);
        patch_branch_cond(jne_do_div, do_div);

        // sign-extend RAX -> RDX:RAX (cqo/cdq)
        if (is_64) emit8(0x48);
        emit8(0x99);

        // idiv rcx / idiv ecx
        if (is_64) {
            emit8(0x48); emit8(0xF7); emit8(0xF9);
        } else {
            emit8(0xF7); emit8(0xF9);
        }

        if (is_mod) {
            if (is_64) emit8(0x48);
            emit8(0x89); emit8(0xD0);  // mov rax, rdx
        }

        // .done: 热路径直接 fall-through 到恢复 RDX
        // patch 溢出路径的 JMP -> .done
        patch_branch_uncond(jmp_done, size());

    } else {
        // --- Unsigned: 热路径 fall-through，无溢出检查 ---

        // xor edx, edx (清零 RDX 作为无符号高位)
        if (is_64) emit8(0x48);
        emit8(0x31); emit8(0xD2);

        // div rcx / div ecx
        if (is_64) {
            emit8(0x48); emit8(0xF7); emit8(0xF1);
        } else {
            emit8(0xF7); emit8(0xF1);
        }

        if (is_mod) {
            if (is_64) emit8(0x48);
            emit8(0x89); emit8(0xD0);  // mov rax, rdx
        }
    }

    // 热路径 fall-through 到此，跳过 .zero 冷路径
    size_t jmp_restore = size();
    emit8(0xE9); emit32(0);  // JMP .restore

    // .zero: handle divide-by-zero (cold path)
    size_t zero_label = size();
    patch_branch_cond(jz_zero, zero_label);
    if (!is_mod) {
        // DIV by zero: result = 0
        if (is_64) emit8(0x48);
        emit8(0x31); emit8(0xC0);  // xor eax, eax
    }
    // MOD by zero: result = original dst (RAX already holds it)
    // fall through to .restore

    // .restore: 恢复 BPF r5 (RDX)
    patch_branch_uncond(jmp_restore, size());
    pop_reg(X86::RDX);
}
//
// 快速路径：查 TLB，命中则直接得到 host 指针
// 慢速路径：push/pop caller-saved 寄存器，调用 helper_mmu
// R11 用作 TLB 索引寄存器（替代旧方案中的 RDI）
// ---------------------------------------------------------------------------

MemAccessContext X86Emitter::begin_mem_access(uint8_t base_x86_reg,
                                               int16_t offset, int access_size, bool is_write) {
    MemAccessContext ctx{};
    int32_t tlb_off = (int32_t)off_tlb_;

    // Load guest address into RAX from the mapped x86 register, then apply BPF offset
    if (base_x86_reg != X86::RAX) {
        mov_r64(X86::RAX, base_x86_reg);
    }
    if (offset != 0) {
        emit8(0x48); emit8(0x05); emit32((uint32_t)(int32_t)offset); // add rax, offset
    }

    // Compute TLB index into R11: tlb_index(addr) * sizeof(TlbEntry)
    // tlb_index = ((addr>>12) ^ (addr>>20)) & (TLB_SIZE-1)
    // mov r11, rax ; shr r11, 12
    emit8(0x49); emit8(0x89); emit8(0xC3);
    emit8(0x49); emit8(0xC1); emit8(0xEB); emit8(12);
    // mov rcx, rax ; shr rcx, 20 ; xor r11, rcx
    //   xor r11,rcx = REX.WB(0x49) 31 /r  ModRM=0xCB(mod=11 reg=001(rcx) r/m=011(r11+REX.B))
    emit8(0x48); emit8(0x89); emit8(0xC1);
    emit8(0x48); emit8(0xC1); emit8(0xE9); emit8(20);
    emit8(0x49); emit8(0x31); emit8(0xCB);
    // and r11d, (TLB_SIZE-1)
    emit8(0x41); emit8(0x81); emit8(0xE3); emit32(TLB_SIZE - 1);
    // shl r11d, shift  (TlbEntry size is power of 2)
    if constexpr ((sizeof(TlbEntry) & (sizeof(TlbEntry) - 1)) == 0) {
        constexpr int shift = __builtin_ctz(sizeof(TlbEntry));
        emit8(0x41); emit8(0xC1); emit8(0xE3); emit8(shift);
    } else {
        // imul r11d, r11d, sizeof(TlbEntry)
        emit8(0x45); emit8(0x69); emit8(0xDB); emit32(sizeof(TlbEntry));
    }

    constexpr int32_t off_guest_base = (int32_t)offsetof(TlbEntry, guest_base);
    constexpr int32_t off_guest_end  = (int32_t)offsetof(TlbEntry, guest_end);
    constexpr int32_t off_host_base  = (int32_t)offsetof(TlbEntry, host_base);
    constexpr int32_t off_flags      = (int32_t)offsetof(TlbEntry, flags);
    constexpr int32_t off_cow        = (int32_t)offsetof(TlbEntry, cow);

    // Bounds check 1: addr >= entry.guest_base
    sib_op_rax(0x3B, tlb_off + off_guest_base);              // cmp rax, [rbp+r11+guest_base]
    ctx.miss_jumps.push_back(size());
    emit8(0x0F); emit8(0x82); emit32(0);                     // JB .slow

    // Bounds check 2: addr + size <= entry.guest_end
    // 使用 RCX（scratch）而非 RDX（BPF r5），避免破坏 BPF 寄存器
    emit8(0x48); emit8(0x8D); emit8(0x88);                   // lea rcx, [rax + disp32]
    emit32((uint32_t)access_size);
    // cmp rcx, [rbp + r11 + guest_end]
    emit8(0x4A); emit8(0x3B);
    emit8(0x8C);  // ModRM: mod=10, reg=RCX(1), rm=100(SIB)
    emit8(0x1D);  // SIB: scale=00, index=R11(011), base=RBP(101)
    emit32(tlb_off + off_guest_end);
    ctx.miss_jumps.push_back(size());
    emit8(0x0F); emit8(0x87); emit32(0);                     // JA .slow

    if (is_write) {
        // Write permission: flags & PF_W (0x2)
        sib_test_dword(tlb_off + off_flags, 0x2);
        ctx.miss_jumps.push_back(size());
        emit8(0x0F); emit8(0x84); emit32(0);                 // JZ .slow

        // No CoW: !cow
        sib_cmp_byte(tlb_off + off_cow, 0);
        ctx.miss_jumps.push_back(size());
        emit8(0x0F); emit8(0x85); emit32(0);                 // JNE .slow
    }

    // TLB hit: host_ptr = host_base + (addr - guest_base)
    sib_op_rax(0x2B, tlb_off + off_guest_base);              // sub rax, guest_base
    sib_op_rax(0x03, tlb_off + off_host_base);               // add rax, host_base

    // JMP .done (rel32 placeholder)
    ctx.done_jmp = size();
    emit8(0xE9); emit32(0);

    // --- Slow path: TLB miss ---
    ctx.slow_start = size();

    // 保存 caller-saved 的 BPF 寄存器（callee-saved 自动存活）
    spill_caller_saved();

    // 设置 System V ABI 参数：RDI=vm*, RSI=guest_addr, EDX=size
    mov_r64(X86::RDI, X86::RBP);                             // mov rdi, rbp
    // RAX 里的 guest addr 已经被 spill_caller_saved 的 push 指令破坏了？
    // 不会：RAX 是 scratch，不在 caller-saved 列表中，push 不影响它
    mov_r64(X86::RSI, X86::RAX);                             // mov rsi, rax
    emit8(0xBA); emit32((uint32_t)access_size);              // mov edx, size
    call_helper(is_write ? helpers_->mmu_w : helpers_->mmu);

    // 恢复 caller-saved 的 BPF 寄存器
    restore_caller_saved();

    // Test for null (memory violation)
    test_rax_rax();
    ctx.abort_jumps.push_back(size());
    emit8(0x0F); emit8(0x84); emit32(0);                     // JZ .vm_exit

    // .done: RAX = host pointer
    ctx.done_offset = size();
    return ctx;
}

void X86Emitter::finish_mem_access(MemAccessContext& ctx,
                                     std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    // Patch miss jumps -> .slow
    for (size_t off : ctx.miss_jumps) {
        patch_branch_cond(off, ctx.slow_start);
    }
    // Patch fast-path JMP -> .done
    patch_branch_uncond(ctx.done_jmp, ctx.done_offset);
    // Record abort jumps for later patching to .vm_exit
    for (size_t off : ctx.abort_jumps) {
        abort_patches.push_back({off, bpf_index});
    }
}

// ---------------------------------------------------------------------------
// ALU (unified for ALU64 and ALU32)
//
// 操作流程：load_bpf(dst->RAX), load_bpf(src->RCX), ALU, store_bpf(dst<-RAX)
// 由于所有 BPF 寄存器都在 x86 物理寄存器中，load_bpf/store_bpf
// 只是 reg-to-reg mov（或 nop）。
// ---------------------------------------------------------------------------

bool X86Emitter::emit_alu(const bpf_insn* insn, bool is_64) {
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;

    auto load_dst = [&]() {
        load_bpf(insn->dst_reg, X86::RAX);
    };
    auto load_src = [&]() {
        load_bpf(insn->src_reg, X86::RCX);
    };
    auto store_dst = [&]() {
        store_bpf(insn->dst_reg, X86::RAX, is_64);
    };

    // ── MOV (off == 0) ──
    if (op == BPF_MOV && insn->off == 0) {
        if (is_64) {
            if (is_x && insn->dst_reg == insn->src_reg) return true;
        }
        if (is_x) {
            // 直接从源 BPF 寄存器 mov 到目标 BPF 寄存器
            uint8_t src_x86 = BPF_REG_MAP[insn->src_reg];
            uint8_t dst_x86 = BPF_REG_MAP[insn->dst_reg];
            if (!is_64) {
                // 32-bit mov: 拷贝低 32 位并零扩展到 64 位，源寄存器不受影响
                mov_r32(dst_x86, src_x86);
            } else if (dst_x86 != src_x86) {
                mov_r64(dst_x86, src_x86);
            }
        } else {
            // MOV immediate: 需要先写到内存再加载到映射寄存器
            // 或者直接 mov imm 到映射寄存器
            uint8_t dst_x86 = BPF_REG_MAP[insn->dst_reg];
            if (is_64) {
                // mov rax, sign-extended imm32; mov dst, rax
                emit8(0x48); emit8(0xC7); emit8(0xC0); emit32(insn->imm);
                mov_r64(dst_x86, X86::RAX);
            } else {
                // 32-bit: mov eax, imm32 (zero-extends); then mov to dst
                emit8(0xB8); emit32(insn->imm);
                mov_r64(dst_x86, X86::RAX);
            }
        }
        return true;
    }

    // ── NEG ──
    if (op == BPF_NEG) {
        load_dst();
        if (is_64) neg64(); else neg32();
        store_dst();
        return true;
    }

    // ── MOV with sign-extension (off != 0) ──
    if (op == BPF_MOV) {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RAX);
        } else {
            emit8(0x48); emit8(0xB8); emit64((uint64_t)(int64_t)insn->imm);
        }
        if (is_64) {
            switch (insn->off) {
            case 8:  emit8(0x48); emit8(0x0F); emit8(0xBE); emit8(0xC0); break;
            case 16: emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0xC0); break;
            case 32: emit8(0x48); emit8(0x63); emit8(0xC0); break;
            default: return false;
            }
        } else {
            switch (insn->off) {
            case 8:  emit8(0x0F); emit8(0xBE); emit8(0xC0); break;
            case 16: emit8(0x0F); emit8(0xBF); emit8(0xC0); break;
            default: return false;
            }
        }
        store_dst();
        return true;
    }

    // ── END (byte-swap / zero-extend) ──
    if (op == BPF_END) {
        if (is_64) {
            load_dst();
            switch (insn->imm) {
            case 16:
                emit8(0x66); emit8(0xC1); emit8(0xC0); emit8(0x08);
                emit8(0x0F); emit8(0xB7); emit8(0xC0);
                break;
            case 32:
                emit8(0x0F); emit8(0xC8);
                break;
            case 64:
                emit8(0x48); emit8(0x0F); emit8(0xC8);
                break;
            default: return false;
            }
        } else {
            if (!is_x && insn->imm == 64) return true;

            if (is_x) {
                load_dst();
                switch (insn->imm) {
                case 16:
                    emit8(0x66); emit8(0xC1); emit8(0xC0); emit8(0x08);
                    emit8(0x0F); emit8(0xB7); emit8(0xC0);
                    break;
                case 32:
                    emit8(0x0F); emit8(0xC8);
                    break;
                case 64: return false;
                default: return false;
                }
            } else {
                switch (insn->imm) {
                case 16:
                    load_dst();
                    emit8(0x25); emit32(0xFFFF);
                    break;
                case 32:
                    load_dst();
                    emit8(0x89); emit8(0xC0);
                    break;
                default: return false;
                }
            }
        }
        store_dst();
        return true;
    }

    // ── Peephole: no-op operations ──
    if (!is_x) {
        if (insn->imm == 0 && (op == BPF_ADD || op == BPF_SUB || op == BPF_OR ||
            op == BPF_XOR || op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)) {
            return true;
        }
        if (insn->imm == 1 && (op == BPF_MUL || op == BPF_DIV)) {
            return true;
        }
    }

    // ── Arithmetic / logic / shift ──
    constexpr uint8_t shift_mask_64 = 0x3F;
    constexpr uint8_t shift_mask_32 = 0x1F;

    load_dst();
    if (is_x) load_src();

    switch (op) {
    case BPF_ADD:  is_x ? (is_64 ? add64() : add32()) : (is_64 ? add64_imm(insn->imm) : add32_imm(insn->imm)); break;
    case BPF_SUB:  is_x ? (is_64 ? sub64() : sub32()) : (is_64 ? sub64_imm(insn->imm) : sub32_imm(insn->imm)); break;
    case BPF_OR:   is_x ? (is_64 ? or64()  : or32())  : (is_64 ? or64_imm(insn->imm)  : or32_imm(insn->imm));  break;
    case BPF_AND:  is_x ? (is_64 ? and64() : and32()) : (is_64 ? and64_imm(insn->imm) : and32_imm(insn->imm)); break;
    case BPF_XOR:  is_x ? (is_64 ? xor64() : xor32()) : (is_64 ? xor64_imm(insn->imm) : xor32_imm(insn->imm)); break;
    case BPF_LSH:
        if (is_x) { if (is_64) shl64_cl(); else shl32_cl(); }
        else { if (is_64) shl64_imm(insn->imm & shift_mask_64); else shl32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_RSH:
        if (is_x) { if (is_64) shr64_cl(); else shr32_cl(); }
        else { if (is_64) shr64_imm(insn->imm & shift_mask_64); else shr32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_ARSH:
        if (is_x) { if (is_64) sar64_cl(); else sar32_cl(); }
        else { if (is_64) sar64_imm(insn->imm & shift_mask_64); else sar32_imm(insn->imm & shift_mask_32); }
        break;
    case BPF_MUL:  is_x ? (is_64 ? mul64() : mul32()) : (is_64 ? mul64_imm(insn->imm) : mul32_imm(insn->imm)); break;
    case BPF_DIV: {
        if (!is_x) {
            // 除以常量 0：结果为 0
            if (insn->imm == 0) {
                if (is_64) emit8(0x48);
                emit8(0x31); emit8(0xC0);  // xor eax, eax
                store_dst();
                return true;
            }
            // 无符号除以 2 的幂（正数）：用右移代替
            if (insn->off == 0 && insn->imm > 0 && (insn->imm & (insn->imm - 1)) == 0) {
                if (is_64) shr64_imm(__builtin_ctz(insn->imm));
                else       shr32_imm(__builtin_ctz(insn->imm));
                store_dst();
                return true;
            }
            emit8(0x48); emit8(0xC7); emit8(0xC1); emit32(insn->imm);  // mov rcx, imm32
        }
        emit_inline_div(is_64, insn->off == 0, false);
        store_dst();
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            // 模常量 0：结果为 dst（不变，RAX 已有 dst 值）
            if (insn->imm == 0) {
                return true;
            }
            // 无符号模 2 的幂（正数）：用 AND 掩码代替
            if (insn->off == 0 && insn->imm > 0 && (insn->imm & (insn->imm - 1)) == 0) {
                if (is_64) and64_imm(insn->imm - 1);
                else       and32_imm(insn->imm - 1);
                store_dst();
                return true;
            }
            emit8(0x48); emit8(0xC7); emit8(0xC1); emit32(insn->imm);
        }
        emit_inline_div(is_64, insn->off == 0, true);
        store_dst();
        return true;
    }
    default: return false;
    }

    store_dst();
    return true;
}

// ---------------------------------------------------------------------------
// LD: load 64-bit immediate
// ---------------------------------------------------------------------------

bool X86Emitter::emit_ld(const bpf_insn* insn) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t sz = insn->code & 0x18;
    if (mode != BPF_IMM || sz != BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    uint64_t imm64 = (uint64_t)(uint32_t)(insn + 1)->imm << 32 | (uint32_t)insn->imm;
    uint8_t dst_x86 = BPF_REG_MAP[insn->dst_reg];

    // mov rax, imm64; mov dst_x86, rax
    emit8(0x48); emit8(0xB8); emit64(imm64);
    mov_r64(dst_x86, X86::RAX);
    return true;
}

// ---------------------------------------------------------------------------
// LDX: load from memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_ldx(const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode != BPF_MEM && mode != BPF_MEMSX) return false;
    if (mode == BPF_MEMSX && size_field == BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;

    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    // 直接从 BPF 源寄存器的映射 x86 寄存器读取基地址，不走内存
    auto ctx = begin_mem_access(BPF_REG_MAP[insn->src_reg], insn->off, access_size, /*is_write=*/false);

    // RAX = host pointer, 从 [RAX] 加载值
    if (mode == BPF_MEM) {
        switch (size_field) {
        case BPF_DW: emit8(0x48); emit8(0x8B); emit8(0x00); break;
        case BPF_W:  emit8(0x8B); emit8(0x00); break;
        case BPF_H:  emit8(0x0F); emit8(0xB7); emit8(0x00); break;
        case BPF_B:  emit8(0x0F); emit8(0xB6); emit8(0x00); break;
        }
    } else {
        switch (size_field) {
        case BPF_W:  emit8(0x48); emit8(0x63); emit8(0x00); break;
        case BPF_H:  emit8(0x48); emit8(0x0F); emit8(0xBF); emit8(0x00); break;
        case BPF_B:  emit8(0x48); emit8(0x0F); emit8(0xBE); emit8(0x00); break;
        default: return false;
        }
    }

    // 将结果从 RAX 移到目标 BPF 寄存器的映射
    mov_r64(BPF_REG_MAP[insn->dst_reg], X86::RAX);
    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// ST: store immediate to memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_st(const bpf_insn* insn,
                           std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode != BPF_MEM) return false;

    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, access_size, /*is_write=*/true);

    // [RAX] = immediate
    switch (size_field) {
    case BPF_DW: emit8(0x48); emit8(0xC7); emit8(0x00); emit32(insn->imm); break;
    case BPF_W:  emit8(0xC7); emit8(0x00); emit32(insn->imm); break;
    case BPF_H:  emit8(0x66); emit8(0xC7); emit8(0x00); emit16((uint16_t)insn->imm); break;
    case BPF_B:  emit8(0xC6); emit8(0x00); emit8((uint8_t)insn->imm); break;
    }

    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX: store register to memory with inline TLB
// ---------------------------------------------------------------------------

bool X86Emitter::emit_stx(const bpf_insn* insn,
                            std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t mode = insn->code & 0xe0;
    uint8_t size_field = insn->code & 0x18;
    if (mode == BPF_ATOMIC) return emit_stx_atomic(insn, abort_patches, bpf_index);
    if (mode != BPF_MEM) return false;

    int access_size;
    switch (size_field) {
    case BPF_DW: access_size = 8; break;
    case BPF_W:  access_size = 4; break;
    case BPF_H:  access_size = 2; break;
    case BPF_B:  access_size = 1; break;
    default: return false;
    }

    // 基址和源值都在 BPF 映射的 x86 寄存器中，begin_mem_access 只踩 RAX/RCX/R11
    // BPF 寄存器映射不使用这三个，所以源值寄存器安全
    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, access_size, /*is_write=*/true);

    // 将源值从映射寄存器加载到 RCX
    load_bpf(insn->src_reg, X86::RCX);

    // [RAX] = RCX (source value)
    switch (size_field) {
    case BPF_DW: emit8(0x48); emit8(0x89); emit8(0x08); break;  // mov [rax], rcx
    case BPF_W:  emit8(0x89); emit8(0x08); break;                // mov [rax], ecx
    case BPF_H:  emit8(0x66); emit8(0x89); emit8(0x08); break;   // mov [rax], cx
    case BPF_B:  emit8(0x88); emit8(0x08); break;                // mov [rax], cl
    }

    finish_mem_access(ctx, abort_patches, bpf_index);
    return true;
}

// ---------------------------------------------------------------------------
// STX atomic: locked read-modify-write
// ---------------------------------------------------------------------------

bool X86Emitter::emit_stx_atomic(const bpf_insn* insn,
                                    std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    uint8_t size_field = insn->code & 0x18;
    if (size_field != BPF_DW && size_field != BPF_W) return false;

    bool is_dw = (size_field == BPF_DW);
    int access_size = is_dw ? 8 : 4;

    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, access_size, /*is_write=*/true);

    // 从映射寄存器加载源值到 RCX（BPF 映射寄存器在 begin_mem_access 后安全）
    load_bpf(insn->src_reg, X86::RCX);

    // RDX = host pointer (save RAX which holds host ptr)
    // 注意：RDX 是 BPF r5 的映射！但这里我们正在做原子操作，
    // 而 RDX 在 begin_mem_access 的 bounds check 中已经被 lea rdx, [rax+size] 踩了。
    // 需要用另一个 scratch 寄存器保存 host ptr。
    // 用 R11 (scratch) 保存 host pointer
    emit8(0x49); emit8(0x89); emit8(0xC3);  // mov r11, rax

    // 保存 RDX (BPF r5) 到 vm->reg[5] — CAS 循环会用 RDX 做临时寄存器
    store_r64((int32_t)(off_reg_ + 5 * 8), X86::RDX);

    int32_t atom_op = insn->imm;
    bool ok = true;

    if (atom_op == (BPF_OR  | BPF_FETCH) ||
        atom_op == (BPF_AND | BPF_FETCH) ||
        atom_op == (BPF_XOR | BPF_FETCH)) {
        uint8_t alu_opcode = ((atom_op & ~BPF_FETCH) == BPF_OR)  ? 0x09
                            : ((atom_op & ~BPF_FETCH) == BPF_AND) ? 0x21
                            : 0x31;

        // CAS loop: load current, compute new, cmpxchg
        size_t loop_start = size();

        // mov rax, [r11]
        if (is_dw) {
            emit8(0x49); emit8(0x8B); emit8(0x03);
        } else {
            emit8(0x41); emit8(0x8B); emit8(0x03);
        }

        // mov rdx, rax (save old value, use RDX as temp — it will be restored later)
        // 注意：这里会覆盖 BPF r5(RDX)，但原子 FETCH 操作后会把旧值写入 src_reg
        if (is_dw) emit8(0x48);
        emit8(0x89); emit8(0xC2);  // mov rdx, rax
        // alu rdx, rcx (compute new value)
        if (is_dw) emit8(0x48);
        emit8(alu_opcode); emit8(0xCA);  // op rdx, rcx

        // lock cmpxchg [r11], rdx
        emit8(0xF0);
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(0x0F); emit8(0xB1); emit8(0x13);  // cmpxchg [r11], rdx

        // jnz loop
        emit8(0x75);
        emit8(0);
        auto loop_end = size();
        int8_t rel = (int8_t)(loop_start - loop_end);
        data()[loop_end - 1] = (uint8_t)rel;

        // FETCH: 将旧值 (RAX) 写入 src_reg
        store_bpf(insn->src_reg, X86::RAX, true);
    } else switch (atom_op) {
    case BPF_ADD | BPF_FETCH:
        // lock xadd [r11], rcx
        emit8(0xF0);
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(0x0F); emit8(0xC1); emit8(0x0B);  // xadd [r11], rcx
        store_bpf(insn->src_reg, X86::RCX, true);
        break;
    case BPF_ADD:
        // lock add [r11], rcx
        emit8(0xF0);
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(0x01); emit8(0x0B);  // add [r11], rcx
        break;

    case BPF_OR:
    case BPF_AND:
    case BPF_XOR: {
        uint8_t opcode = (atom_op == BPF_OR) ? 0x09
                       : (atom_op == BPF_AND) ? 0x21
                       : 0x31;
        emit8(0xF0);
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(opcode); emit8(0x0B);  // op [r11], rcx
        break;
    }

    case BPF_XCHG:
        // xchg [r11], rcx
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(0x87); emit8(0x0B);  // xchg [r11], rcx
        store_bpf(insn->src_reg, X86::RCX, true);
        break;

    case BPF_CMPXCHG:
        // RAX = BPF r0 for cmpxchg
        load_bpf(0, X86::RAX);
        emit8(0xF0);
        if (is_dw) emit8(0x49); else emit8(0x41);
        emit8(0x0F); emit8(0xB1); emit8(0x0B);  // lock cmpxchg [r11], rcx
        // 结果回写 r0
        store_bpf(0, X86::RAX, true);
        break;

    default:
        ok = false;
        break;
    }

    // 统一恢复 RDX (BPF r5) 并完成内存访问
    load_r64(X86::RDX, (int32_t)(off_reg_ + 5 * 8));
    finish_mem_access(ctx, abort_patches, bpf_index);
    return ok;
}

// ---------------------------------------------------------------------------
// Conditional jumps
// ---------------------------------------------------------------------------

bool X86Emitter::emit_jmp(const bpf_insn* insn, int current_index, bool is_64,
                            std::vector<JumpPlaceholder>& placeholders) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;

    if (is_64) {
        if (op == BPF_JA || op == BPF_CALL || op == BPF_EXIT) return false;
    } else {
        if (op == BPF_JA) return false;
    }

    uint8_t x86_cc = 0;
    bool is_test = false;

    switch (op) {
    case BPF_JEQ:  x86_cc = 0x84; break;
    case BPF_JNE:  x86_cc = 0x85; break;
    case BPF_JGT:  x86_cc = 0x87; break;
    case BPF_JGE:  x86_cc = 0x83; break;
    case BPF_JLT:  x86_cc = 0x82; break;
    case BPF_JLE:  x86_cc = 0x86; break;
    case BPF_JSGT: x86_cc = 0x8F; break;
    case BPF_JSGE: x86_cc = 0x8D; break;
    case BPF_JSLT: x86_cc = 0x8C; break;
    case BPF_JSLE: x86_cc = 0x8E; break;
    case BPF_JSET: x86_cc = 0x85; is_test = true; break;
    default: return false;
    }

    load_bpf(insn->dst_reg, X86::RAX);

    if (is_test) {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RCX);
            if (is_64) test64(); else test32();
        } else {
            if (is_64) test64_imm(insn->imm); else test32_imm(insn->imm);
        }
    } else {
        if (is_x) {
            load_bpf(insn->src_reg, X86::RCX);
            if (is_64) cmp64(); else cmp32();
        } else {
            if (is_64) cmp64_imm(insn->imm); else cmp32_imm(insn->imm);
        }
    }

    size_t jcc_off = size();
    jcc_rel32(x86_cc);

    int target = current_index + 1 + insn->off;
    placeholders.push_back({jcc_off, target, PlaceholderKind::Conditional});
    return true;
}

// ---------------------------------------------------------------------------
// Unconditional jumps
// ---------------------------------------------------------------------------

void X86Emitter::emit_ja(const bpf_insn* insn, int current_index,
                           std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = size();
    jmp_rel32();
    int target = current_index + 1 + insn->off;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Unconditional});
}

void X86Emitter::emit_ja32(const bpf_insn* insn, int current_index,
                             std::vector<JumpPlaceholder>& placeholders) {
    size_t jmp_off = size();
    jmp_rel32();
    int target = current_index + 1 + insn->imm;
    placeholders.push_back({jmp_off, target, PlaceholderKind::Unconditional});
}

// ---------------------------------------------------------------------------
// CALL syscall (src_reg==0)
//
// Syscall 可能读写任意 BPF 寄存器，所以需要完整 flush + reload。
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_syscall(const bpf_insn* insn, int current_index,
                                      uint64_t entry_gpa) {
    // 完整 flush 所有 BPF 寄存器到 vm->reg[]
    flush_to_vm();

    // 保存当前 pc（guest 地址）到 vm->pc
    uint64_t insn_gpa = entry_gpa + (uint64_t)current_index * sizeof(bpf_insn);
    mov_rax_imm64(insn_gpa);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);  // mov [rbp+off_pc], rax

    // 调用 helper_do_syscall(vm*, call_id)
    mov_r64(X86::RDI, X86::RBP);                              // mov rdi, rbp
    emit8(0xBE); emit32((uint32_t)insn->imm);                 // mov esi, call_id
    call_helper(helpers_->do_syscall);

    // 检查返回值
    test_al_al();
    size_t jz_off = size();
    emit8(0x0F); emit8(0x84); emit32(0);  // JZ .vm_exit
    patch_branch_cond(jz_off, vm_exit_offset);

    // 完整 reload 所有 BPF 寄存器（syscall 可能改了任意寄存器）
    reload_from_vm();
}

// ---------------------------------------------------------------------------
// CALL softfp_slow — FP 虚拟指令（src_reg=2）的 JIT 回退路径。
//
// 当 emit_call_softfp 无法原生 lower（如 x86 缺少 AVX-512 的 uint fp<->int 转换）
// 时走此路径：flush 寄存器 -> 调 helper_do_softfp(vm*, call_id) -> reload。
//
// 与 emit_call_syscall 结构相同，但调 do_softfp（只读 r1/r2、写 r0，不会导致
// VM exit），故无需检查返回值——helper_do_softfp 无条件返回 true。
// ---------------------------------------------------------------------------
void X86Emitter::emit_call_softfp_slow(const bpf_insn* insn, int current_index,
                                         uint64_t entry_gpa) {
    flush_to_vm();

    // 保存当前 pc（guest 地址）到 vm->pc
    uint64_t insn_gpa = entry_gpa + (uint64_t)current_index * sizeof(bpf_insn);
    mov_rax_imm64(insn_gpa);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);  // mov [rbp+off_pc], rax

    // 调用 helper_do_softfp(vm*, call_id)
    mov_r64(X86::RDI, X86::RBP);                              // mov rdi, rbp
    emit8(0xBE); emit32((uint32_t)insn->imm);                 // mov esi, call_id
    call_helper(helpers_->do_softfp);

    // do_softfp 只写 r0、不改其他寄存器语义外的东西，但 reload 以保持一致与安全。
    reload_from_vm();
}

// ---------------------------------------------------------------------------
// 虚拟浮点指令的 JIT 实现（x86_64）。
//
// 寄存器驻留：JIT 把全部 11 个 BPF 寄存器常驻在 x86 物理寄存器，纯计算路径
// 不碰 vm->reg[]。故到一条 BPF_FP_* 时 r1/r2/r0 已在 R9/R10/R8，直接读
// -> SSE 运算 -> 写回 R8 即可，无需 flush/reload 或退 JIT。
// scratch：RAX/RCX（整数）、xmm0/xmm1（浮点），均 caller-saved。
//
// float 的位模式也按 i64 整体搬（与 do_softfp 传位方式一致），低 32 位有效、
// 高位为 0，不影响算术结果。
//
// 返回 true 表示已用原生指令处理；false 表示交给通用 syscall 路径（do_softfp）。
// ---------------------------------------------------------------------------

bool X86Emitter::emit_call_softfp(const bpf_insn* insn) {
    const uint32_t imm = (uint32_t)insn->imm;

    // BPF 寄存器 -> x86 寄存器（与 BPF_REG_MAP 一致）。
    const uint8_t R_R0 = X86::R8;   // 结果
    const uint8_t R_R1 = X86::R9;   // 操作数 a
    const uint8_t R_R2 = X86::R10;  // 操作数 b
    const uint8_t X0 = 0;           // xmm0
    const uint8_t X1 = 1;           // xmm1
    const uint8_t X2 = 2;           // xmm2（掩码暂存）

    // 双精度二元算术：xmm0 = a (op) b
    auto emit_d_binop = [&](uint8_t op) {
        sse_movq_xmm_r64(X0, R_R1);
        sse_movq_xmm_r64(X1, R_R2);
        sse_alu_scalar(0xF2, op, X0, X1);   // xmm0 (op)= xmm1
        sse_movq_r64_xmm(R_R0, X0);
    };
    // 单精度二元算术（操作数位模式仍在 R9/R10 低 32 位，movq 整体搬无碍）。
    auto emit_f_binop = [&](uint8_t op) {
        sse_movq_xmm_r64(X0, R_R1);
        sse_movq_xmm_r64(X1, R_R2);
        sse_alu_scalar(0xF3, op, X0, X1);
        // 结果在 xmm0 低 32 位；movd 取低 32 位到 RAX，再零扩展搬进 R8。
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
    };
    // 比较：GCC 软浮点 ABI 返回 int 三态（<0/=0/>0）。用 UCOMISx 设 EFLAGS
    // （UCOMI 对无序不触发 #IA，仅置 PF=1）。UCOMISD EFLAGS 真值表：
    //     a > b      -> ZF=0, CF=0      a == b    -> ZF=1, CF=0
    //     a < b      -> ZF=0, CF=1      无序(NaN) -> ZF=1, CF=1
    // 先置默认结果 1（仅 a>b 落到此值），再按 ZF->0、CF->-1 顺序覆盖：
    //   * a>b：JE/JB 都不跳，r8d 保持 1。
    //   * a==b：JE 命中->r8d=0。
    //   * a<b：JE 不跳(ZF=0)、JB 命中(CF=1)->r8d=-1。
    //   * 无序：JE 命中(ZF=1)->r8d=0（与 do_softfp 一致：NaN 视作相等->0）。
    // 故无序返回 0，而非默认 1——这点与下方各分支语义吻合。
    auto emit_cmp = [&](bool is_double) {
        sse_movq_xmm_r64(X0, R_R1);   // xmm0 = a
        sse_movq_xmm_r64(X1, R_R2);   // xmm1 = b
        if (is_double) sse_ucomisd(X0, X1);  // 比较 a, b
        else           sse_ucomiss(X0, X1);
        emit8(0x41); emit8(0xB8); emit32(1);          // mov r8d, 1
        size_t jz_off = size();
        emit8(0x0F); emit8(0x84); emit32(0);          // JE .eq (rel32, ZF=1)
        size_t jb_off = size();
        emit8(0x0F); emit8(0x82); emit32(0);          // JB .lt (rel32, CF=1)
        // .gt：fall-through（r8d 已是 1）-> JMP .done
        size_t gt_jmp = size();
        emit8(0xE9); emit32(0);                        // JMP .done
        // .eq: r8d = 0
        size_t eq_off = size();
        patch_branch_cond(jz_off, eq_off);
        emit8(0x41); emit8(0xB8); emit32(0);
        size_t eq_jmp = size();
        emit8(0xE9); emit32(0);                        // JMP .done
        // .lt: r8d = -1
        size_t lt_off = size();
        patch_branch_cond(jb_off, lt_off);
        emit8(0x41); emit8(0xB8); emit32((uint32_t)-1);
        // .done：.lt 是最后一块，直接 fall-through 即到 .done，故无需再发 JMP。
        size_t done_off = size();
        patch_branch_uncond(gt_jmp, done_off);
        patch_branch_uncond(eq_jmp, done_off);
    };
    // 无序判定（__unordXX2）：任一操作数为 NaN -> r0=1，否则 r0=0。
    // UCOMISx 之后 PF=1 表示无序（NaN）。先默认 0（有序），PF=1 时覆盖成 1：
    //   mov r8d, 0          ; 默认有序
    //   JNP .done           ; PF=0(有序) 直接跳过（JNP = 0F 8B）
    //   mov r8d, 1          ; PF=1(无序)
    // .done:
    auto emit_unord = [&](bool is_double) {
        sse_movq_xmm_r64(X0, R_R1);   // xmm0 = a
        sse_movq_xmm_r64(X1, R_R2);   // xmm1 = b
        if (is_double) sse_ucomisd(X0, X1);
        else           sse_ucomiss(X0, X1);
        emit8(0x41); emit8(0xB8); emit32(0);          // mov r8d, 0（默认：有序）
        size_t jnp_off = size();
        emit8(0x0F); emit8(0x8B); emit32(0);          // JNP .done（PF=0 即有序时跳过）
        emit8(0x41); emit8(0xB8); emit32(1);          // mov r8d, 1（无序：有 NaN）
        patch_branch_cond(jnp_off, size());
    };

    switch (imm) {
    // —— 双精度算术 ——
    case BPF_FP_ADD_D: emit_d_binop(0x58); return true;
    case BPF_FP_SUB_D: emit_d_binop(0x5C); return true;
    case BPF_FP_MUL_D: emit_d_binop(0x59); return true;
    case BPF_FP_DIV_D: emit_d_binop(0x5E); return true;

    // —— 单精度算术 ——
    case BPF_FP_ADD_F: emit_f_binop(0x58); return true;
    case BPF_FP_SUB_F: emit_f_binop(0x5C); return true;
    case BPF_FP_MUL_F: emit_f_binop(0x59); return true;
    case BPF_FP_DIV_F: emit_f_binop(0x5E); return true;

    // —— 取负（异或符号位掩码）——
    case BPF_FP_NEG_D: {
        sse_movq_xmm_r64(X0, R_R1);
        // mov rcx, 0x8000000000000000 ; xmm1 = 该位模式 ; xorps
        emit8(0x48); emit8(0xB9); emit64(0x8000000000000000ULL);  // mov rcx, imm64
        sse_movq_xmm_r64(X1, X86::RCX);
        sse_xorps(X0, X1);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_NEG_F: {
        // 单精度符号位掩码在低 32 位；用 32 位搬运。
        sse_movd_xmm_r32(X0, R_R1);
        emit8(0xB9); emit32(0x80000000u);                          // mov ecx, imm32
        sse_movd_xmm_r32(X1, X86::RCX);
        sse_xorps(X0, X1);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— 平方根 ——
    case BPF_FP_SQRT_D: {
        sse_movq_xmm_r64(X0, R_R1);
        sse_sqrt_scalar(0xF2, X0, X0);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_SQRT_F: {
        sse_movd_xmm_r32(X0, R_R1);
        sse_sqrt_scalar(0xF3, X0, X0);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— 绝对值（清符号位：andps 0x7FFF...F）——
    case BPF_FP_FABS_D: {
        sse_movq_xmm_r64(X0, R_R1);
        emit8(0x48); emit8(0xB9); emit64(0x7FFFFFFFFFFFFFFFULL);  // mov rcx, 0x7FFF...F
        sse_movq_xmm_r64(X1, X86::RCX);
        sse_andps(X0, X1);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_FABS_F: {
        sse_movd_xmm_r32(X0, R_R1);
        emit8(0xB9); emit32(0x7FFFFFFFu);                          // mov ecx, 0x7FFFFFFF
        sse_movd_xmm_r32(X1, X86::RCX);
        sse_andps(X0, X1);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— copysign(x, y)：取 y 的符号位并到 x 上。
    //   (x & 0x7FFF...F) | (y & 0x8000...0)。xmm0=x, xmm1=y；
    //   先 andps 清 x 符号位，再把 y 的符号位 or 上去。 ——
    case BPF_FP_COPYSIGN_D: {
        sse_movq_xmm_r64(X0, R_R1);           // xmm0 = x
        sse_movq_xmm_r64(X1, R_R2);           // xmm1 = y
        emit8(0x48); emit8(0xB9); emit64(0x7FFFFFFFFFFFFFFFULL);  // mov rcx, mag_mask
        sse_movq_xmm_r64(X2, X86::RCX);
        sse_andps(X0, X2);                    // xmm0 = x 清符号位
        emit8(0x48); emit8(0xB9); emit64(0x8000000000000000ULL);  // mov rcx, sign_mask
        sse_movq_xmm_r64(X2, X86::RCX);
        sse_andps(X1, X2);                    // xmm1 = y 的符号位
        sse_orps(X0, X1);                     // xmm0 = 合并符号
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_COPYSIGN_F: {
        // 单精度：位模式在低 32 位。x->xmm0(低32)，y->xmm1(低32)。
        sse_movq_xmm_r64(X0, R_R1);           // 整 8 字节搬入（高位无所谓）
        sse_movq_xmm_r64(X1, R_R2);
        emit8(0xB9); emit32(0x7FFFFFFFu);                          // mov ecx, mag_mask(32)
        sse_movd_xmm_r32(X2, X86::RCX);
        sse_andps(X0, X2);                    // 清 x 符号位
        emit8(0xB9); emit32(0x80000000u);                          // mov ecx, sign_mask(32)
        sse_movd_xmm_r32(X2, X86::RCX);
        sse_andps(X1, X2);                    // y 的符号位
        sse_orps(X0, X1);                     // 合并
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— double -> 有符号整数（向 0 截断）——
    case BPF_FP_D2SI:
    case BPF_FP_D2DI: {
        sse_movq_xmm_r64(X0, R_R1);
        sse_cvtsd2si(R_R0, X0);   // 64 位结果；D2SI 取低 32 位（调用方 w0 零扩展）
        return true;
    }
    // —— float -> 有符号整数 ——
    case BPF_FP_F2SI:
    case BPF_FP_F2DI: {
        sse_movq_xmm_r64(X0, R_R1);
        sse_cvtss2si(R_R0, X0);
        return true;
    }

    // —— int -> double（src 在 R9，按宽度做有符号解释）——
    case BPF_FP_DI2D: {   // int64 -> double
        sse_cvtsi2sd(X0, R_R1, true);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_SI2D: {   // int32 -> double（符号扩展后转换）
        // cvtsi2sd 的 32 位源读 R9D（低 32 位，符号扩展到 int32）。不需要显式扩展。
        sse_cvtsi2sd(X0, R_R1, false);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    // —— int -> float ——
    case BPF_FP_DI2F: {
        sse_cvtsi2ss(X0, R_R1, true);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }
    case BPF_FP_SI2F: {
        sse_cvtsi2ss(X0, R_R1, false);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— 类型转换 ——
    case BPF_FP_EXTEND: {  // float -> double
        sse_movd_xmm_r32(X0, R_R1);
        sse_cvtss2sd(X0, X0);
        sse_movq_r64_xmm(R_R0, X0);
        return true;
    }
    case BPF_FP_TRUNC: {   // double -> float
        sse_movq_xmm_r64(X0, R_R1);
        sse_cvtsd2ss(X0, X0);
        sse_movd_r32_xmm(X86::RAX, X0);
        mov_r64(R_R0, X86::RAX);
        return true;
    }

    // —— 比较：见上方 emit_cmp lambda ——
    case BPF_FP_CMP_D: emit_cmp(true);  return true;
    case BPF_FP_CMP_F: emit_cmp(false); return true;

    // —— 无序判定：见上方 emit_unord lambda ——
    case BPF_FP_UNORD_D: emit_unord(true);  return true;
    case BPF_FP_UNORD_F: emit_unord(false); return true;

    // 整数宽乘取高半：r0 = (a*b)>>64，用 x86 mulq（RDX:RAX = RAX*RCX）。
    // mulq 破坏 RDX(=BPF r5) 不需保护：softfp call 的 r1~r5 是 caller-saved
    //（同 fadd/fsub 等；emit_inline_div 那种内联 ALU 才需保护）。
    case BPF_FP_UMULH: {
        mov_r64(X86::RAX, R_R1);                    // rax = a
        mov_r64(X86::RCX, R_R2);                    // rcx = b
        emit8(0x48); emit8(0xF7); emit8(0xE1);      // mul rcx：RDX:RAX = RAX*RCX
        mov_r64(R_R0, X86::RDX);                    // hi(RDX) -> r0
        return true;
    }

    default:
        // 未实现的 FP 编号（主要是 uint 目标的转换 D2USI/D2UDI/F2USI/F2UDI
        // 及对应的 int->fp 无符号源 USI2*/UDI2*，x86 无直接指令）交给通用 syscall。
        return false;
    }
}


// ---------------------------------------------------------------------------
// CALL BPF-to-BPF (src_reg==1)
//
// fast path（flags==0、callee 已缓存）零 C 调用、零 flush/reload：
//   flags-check -> 内联 push_frame -> inline cache -> 命中 call r11 进 entry_fast
//   -> callee 经 vm_exit ret 回 .cont（只 reload r10 + flag-check + pc-check）。
//   r0=R8（vm_exit 不 pop）、r6-r9/RBP（callee-saved 由 pop 还原）、r1-r5 失效，故无 reload。
//
// .slow_resolve（cache miss）：spill r0-r5 护参 -> helper_resolve_and_cache（查 callee、
//   命中填槽）-> restore -> call r11。
// .not_compiled：未编译 -> flush + vm_exit 回 step() 编译 callee。
// .slow：flags!=0 -> helper_call_bpf（push_frame+设 pc）-> vm_exit。
// .overflow：栈溢出 -> VM_KILLED -> vm_exit。
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_bpf(uint64_t ret_gpa, uint64_t callee_gpa,
                               std::vector<AbortPatchInfo>& abort_patches, int bpf_index,
                               std::vector<size_t>& call_cache_offs) {
    // -  调用点 safepoint：flags!=0 走 .slow
    emit8(0x83); emit8(modrm(2, 7, X86::RBP)); emit32((uint32_t)off_flags_);
    emit8(0x00);                            // cmp dword [rbp+off_flags], 0
    size_t flags_jnz = size();
    emit8(0x0F); emit8(0x85); emit32(0);    // JNZ .slow
    // entry_fast 信任 x86 寄存器（见 entry_fast 注释），故 fast path 无 flush。

    // -  内联 push_frame（仅用 RAX/RCX/R11 scratch，不碰 r1-r5 参数与 r6-r9/r10）
    // 2a. 读 cur_frame[0]（caller 帧头 total_len 在低 32 位）
    auto rctx = begin_mem_access(X86::R15, 0, 8, /*is_write=*/false);  // RAX = cur_frame host
    emit8(0x48); emit8(0x8B); emit8(0x08);  // mov rcx, [rax]  (cur_frame[0])
    emit8(0x89); emit8(0xC9);                // mov ecx, ecx    (total_len = 低32, 零扩展)
    mov_r64(X86::RAX, X86::R15);             // mov rax, r15    (rax = r10 = old sp)
    sub64();                                 // sub rax, rcx    (rax = r10 - caller_total_len)
    sub64_imm(64);                           // sub rax, 64     (rax = frame_base)
    cmp64_imm((int32_t)STACK_BASE);          // cmp rax, STACK_BASE
    size_t overflow_jb = size();
    emit8(0x0F); emit8(0x82); emit32(0);     // JB .overflow (frame_base < STACK_BASE)
    store_r64((int32_t)off_scratch_, X86::RAX);  // 暂存 frame_base（write-probe 会踩 scratch）
    finish_mem_access(rctx, abort_patches, bpf_index);

    // 2b. 写新帧 [frame_base, 64)（含 !cow 检查，覆盖 fork 后栈 CoW）
    auto wctx = begin_mem_access(X86::RAX, 0, 64, /*is_write=*/true);  // RAX = 帧 host
    //   [rax+0]  = stack_limit（frame_flags_make(false, stack_limit) = stack_limit）
    load_r64(X86::RCX, (int32_t)off_stack_limit_);
    emit8(0x48); emit8(0x89); emit8(0x08);                 // mov [rax], rcx
    //   [rax+8]  = old r10 (R15，尚未更新)
    emit8(0x4C); emit8(0x89); emit8(0x78); emit8(0x08);   // mov [rax+8], r15
    //   [rax+16] = ret_gpa
    emit8(0x48); emit8(0xB9); emit64(ret_gpa);            // mov rcx, ret_gpa
    emit8(0x48); emit8(0x89); emit8(0x48); emit8(0x10);   // mov [rax+0x10], rcx
    //   [rax+24..48] = r6..r9 (RBX/R12/R13/R14)
    emit8(0x48); emit8(0x89); emit8(0x58); emit8(0x18);   // mov [rax+0x18], rbx
    emit8(0x4C); emit8(0x89); emit8(0x60); emit8(0x20);   // mov [rax+0x20], r12
    emit8(0x4C); emit8(0x89); emit8(0x68); emit8(0x28);   // mov [rax+0x28], r13
    emit8(0x4C); emit8(0x89); emit8(0x70); emit8(0x30);   // mov [rax+0x30], r14
    //   r10 = frame_base（从暂存读回）。同步 vm->reg[10]：entry_fast 不 load r10，
    //   R15 即真理源；且 .not_compiled 时 step 经正常入口也从 vm->reg[10] 读。
    load_r64(X86::R15, (int32_t)off_scratch_);            // mov r15, [rbp+off_scratch]
    store_r64((int32_t)(off_reg_ + 10 * 8), X86::R15);     // mov [rbp+reg+10*8], r15
    finish_mem_access(wctx, abort_patches, bpf_index);

    // -  inline cache：mov rax, [slot_addr]; test; jz .slow_resolve
    size_t slot_imm_off = size() + 2;                      // imm64 在 mov rax,imm64 中的偏移
    emit8(0x48); emit8(0xB8); emit64(0);                   // mov rax, <slot_addr>（占位）
    call_cache_offs.push_back(slot_imm_off);              // compile() patch 成 &call_cache[idx]
    emit8(0x48); emit8(0x8B); emit8(0x00);                // mov rax, [rax]（缓存 target）
    test_rax_rax();
    size_t cache_jz = size();
    emit8(0x0F); emit8(0x84); emit32(0);                  // JZ .slow_resolve

    // -  cache 命中：call r11 进 entry_fast。RBP 已是 vm*，无需 mov rdi,rbp（RDI=r3，会踩参数）。
    emit8(0x4C); emit8(0x8B); emit8(0xD8);               // mov r11, rax
    emit8(0x41); emit8(0xFF); emit8(0xD3);                // call r11
    size_t after_call_jmp = size();
    emit8(0xE9); emit32(0);                               // jmp .cont（占位）

    // -  .slow_resolve（cache miss）：spill r0-r5 护参 -> 查 callee 填槽 -> restore -> call r11
    size_t slow_resolve = size();
    patch_branch_cond(cache_jz, slow_resolve);
    spill_caller_saved();
    mov_r64(X86::RDI, X86::RBP);                          // mov rdi, rbp（vm*，helper 入参）
    emit8(0x48); emit8(0xBE); emit64(callee_gpa);        // mov rsi, callee_gpa
    emit8(0x48); emit8(0xBA);                             // mov rdx, <slot_addr>（占位）
    size_t slot_arg_off = size();
    emit64(0);
    call_cache_offs.push_back(slot_arg_off);
    call_helper(helpers_->resolve_and_cache);
    restore_caller_saved();
    test_rax_rax();
    size_t nc_jz = size();
    emit8(0x0F); emit8(0x84); emit32(0);                  // JZ .not_compiled
    emit8(0x4C); emit8(0x8B); emit8(0xD8);               // mov r11, rax
    emit8(0x41); emit8(0xFF); emit8(0xD3);                // call r11
    size_t sr_jmp = size();
    emit8(0xE9); emit32(0);                               // jmp .cont

    // -  .not_compiled：未编译。step 经正常入口从 vm->reg[] load r0-r9，故须 flush（r10 已写）。
    size_t not_compiled = size();
    patch_branch_cond(nc_jz, not_compiled);
    flush_to_vm();
    size_t nc_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(nc_jmp, vm_exit_offset);

    // -  .slow：flags!=0 -> helper_call_bpf（push_frame+设 pc）-> vm_exit
    size_t slow = size();
    patch_branch_cond(flags_jnz, slow);
    flush_to_vm();
    mov_r64(X86::RDI, X86::RBP);
    emit8(0x48); emit8(0xBE); emit64(ret_gpa);
    emit8(0x48); emit8(0xBA); emit64(callee_gpa);
    call_helper(helpers_->call_bpf);
    size_t slow_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(slow_jmp, vm_exit_offset);

    // -  .overflow：栈溢出 -> VM_KILLED -> vm_exit
    size_t overflow = size();
    patch_branch_cond(overflow_jb, overflow);
    emit8(0xF0); emit8(0x83); emit8(modrm(2, 1, X86::RBP));  // lock or [rbp+off_flags], VM_KILLED
    emit32((uint32_t)off_flags_); emit8(0x04);
    size_t ov_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(ov_jmp, vm_exit_offset);

    // -  .cont：callee 经 vm_exit ret 返回。无 reload——r0=R8、r6-r9/RBP 由 pop 还原。
    //    唯 r10 须 reload（pop 还原 callee 入口 r10=frame_base，caller 需 old_sp，emit_exit
    //    已写 vm->reg[10]）。flag-check 捕 VM_JIT_ABORT/信号；pc-check 兜底非正常返回。
    size_t cont_target = size();
    patch_branch_uncond(after_call_jmp, cont_target);
    patch_branch_uncond(sr_jmp, cont_target);
    load_r64(X86::R15, (int32_t)(off_reg_ + 10 * 8));  // r10 = vm->reg[10] (= old_sp)
    emit8(0x83); emit8(modrm(2, 7, X86::RBP)); emit32((uint32_t)off_flags_);
    emit8(0x00);                            // cmp dword [rbp+off_flags], 0
    size_t cont_jnz = size();
    emit8(0x0F); emit8(0x85); emit32(0);    // JNZ vm_exit
    load_r64(X86::RAX, (int32_t)off_pc_);            // mov rax, [rbp+off_pc]
    emit8(0x48); emit8(0xB9); emit64(ret_gpa);       // mov rcx, ret_gpa
    cmp64();                                          // cmp rax, rcx
    size_t cont_jne = size();
    emit8(0x0F); emit8(0x85); emit32(0);    // JNE vm_exit
    patch_branch_cond(cont_jnz, vm_exit_offset);
    patch_branch_cond(cont_jne, vm_exit_offset);
}

// ---------------------------------------------------------------------------
// CALL indirect (BPF_CALL | BPF_X)
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_indirect(const bpf_insn* insn,
                                      uint64_t ret_gpa) {
    // 先 flush 全部寄存器到 vm->reg[]，再从内存读取目标地址到 RDX。
    // 不能在 flush 前 load_bpf(dst_reg, RDX)，否则会覆盖 BPF r5 的值。
    flush_to_vm();
    load_r64(X86::RDX, (int32_t)(off_reg_ + insn->dst_reg * 8));

    mov_r64(X86::RDI, X86::RBP);
    emit8(0x48); emit8(0xBE); emit64(ret_gpa);                // mov rsi, ret_gpa
    call_helper(helpers_->call_indirect);
    // helper_call_indirect 执行后总是需要退出 JIT（pc 已改变或 VM 被终止）
    // 直接跳 vm_exit（flush 已经做过了）
    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(jmp_off, vm_exit_offset);
}

// ---------------------------------------------------------------------------
// EXIT (BPF_EXIT)
//
// 内联 pop_frame：读帧取 ret_addr(frame[2])、old_sp(frame[1])、frame[0] flags，
//   从帧取 r6..r9 写 vm->reg[6..9]（BPF 后端对未用 r6..r9 的函数不 spill/reload，x86 值
//   不可信，必从帧取）；写 vm->reg[0]=r0(R8)、vm->reg[10]=old_sp、vm->pc_=ret_addr。
//   r0 留 R8：fast path 经 vm_exit ret 回 .cont，.cont 用 R8 取返回值，不 reload。
//   信号帧在 frame[7..12] 存被中断处 caller-saved r0..r5，须一并恢复。
// ---------------------------------------------------------------------------

void X86Emitter::emit_exit(std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    // -  内联 pop_frame：读 frame[0..12]（104B，覆盖普通 64B + 信号 128B 的 r0..r5）。
    auto ctx = begin_mem_access(X86::R15, 0, 104, /*is_write=*/false);  // RAX = frame host
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x10);   // mov rcx, [rax+0x10]  (ret_addr = frame[2])
    emit8(0x48); emit8(0x8B); emit8(0x50); emit8(0x08);   // mov rdx, [rax+0x08]  (old_sp = frame[1])
    emit8(0x4C); emit8(0x8B); emit8(0x18);               // mov r11, [rax]      (frame[0] flags，检测 is_signal)
    store_r64((int32_t)off_scratch_, X86::RAX);           // 暂存 frame host（下文 store 复用 RAX）
    finish_mem_access(ctx, abort_patches, bpf_index);

    // -  栈底检查：ret_addr==0 -> 哨兵帧（程序退出），置 VM_EXITED。
    emit8(0x48); emit8(0x85); emit8(0xC9);                 // test rcx, rcx
    size_t stack_bottom_jz = size();
    emit8(0x0F); emit8(0x84); emit32(0);                  // JZ .stack_bottom

    // -  vm->pc_ = ret_addr；vm->reg[0]=r0；r6..r9/10 从帧取写 vm->reg[]。
    store_r64((int32_t)off_pc_, X86::RCX);                 // vm->pc_ = ret_addr
    store_r64((int32_t)(off_reg_ + 0 * 8), X86::R8);       // vm->reg[0] = r0（信号帧下方覆盖）
    load_r64(X86::RAX, (int32_t)off_scratch_);             // RAX = frame host
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x18);   // mov rcx, [rax+0x18]  (r6)
    store_r64((int32_t)(off_reg_ + 6 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x20);   // mov rcx, [rax+0x20]  (r7)
    store_r64((int32_t)(off_reg_ + 7 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x28);   // mov rcx, [rax+0x28]  (r8)
    store_r64((int32_t)(off_reg_ + 8 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x30);   // mov rcx, [rax+0x30]  (r9)
    store_r64((int32_t)(off_reg_ + 9 * 8), X86::RCX);
    store_r64((int32_t)(off_reg_ + 10 * 8), X86::RDX);     // vm->reg[10] = old_sp(frame[1])

    // -  信号帧：r0..r5 从 frame[7..12](@+0x38..0x60) 覆盖写 vm->reg[0..5]。
    //    is_signal = frame[0] bit32。普通帧（bit32=0）跳过。
    emit8(0x49); emit8(0xC1); emit8(0xEB); emit8(32);     // shr r11, 32
    emit8(0x45); emit8(0x85); emit8(0xDB);                 // test r11d, r11d
    size_t sig_je = size();
    emit8(0x0F); emit8(0x84); emit32(0);                   // JE .no_signal
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x38);   // mov rcx, [rax+0x38]  (r0)
    store_r64((int32_t)(off_reg_ + 0 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x40);   // mov rcx, [rax+0x40]  (r1)
    store_r64((int32_t)(off_reg_ + 1 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x48);   // mov rcx, [rax+0x48]  (r2)
    store_r64((int32_t)(off_reg_ + 2 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x50);   // mov rcx, [rax+0x50]  (r3)
    store_r64((int32_t)(off_reg_ + 3 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x58);   // mov rcx, [rax+0x58]  (r4)
    store_r64((int32_t)(off_reg_ + 4 * 8), X86::RCX);
    emit8(0x48); emit8(0x8B); emit8(0x48); emit8(0x60);   // mov rcx, [rax+0x60]  (r5)
    store_r64((int32_t)(off_reg_ + 5 * 8), X86::RCX);
    size_t no_signal = size();
    patch_branch_cond(sig_je, no_signal);

    size_t exit_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(exit_jmp, vm_exit_offset);

    // -  .stack_bottom：flush r0(退出码) + 置 VM_EXITED + vm_exit
    size_t stack_bottom = size();
    patch_branch_cond(stack_bottom_jz, stack_bottom);
    store_r64((int32_t)(off_reg_ + 0 * 8), X86::R8);       // vm->reg[0] = 退出码
    emit8(0xF0); emit8(0x83); emit8(0x8D); emit32((uint32_t)off_flags_); emit8(0x01);
    size_t sb_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(sb_jmp, vm_exit_offset);
}

// ---------------------------------------------------------------------------
// Prologue
//
// 入口：RDI = vm* 指针
// 保存 callee-saved 寄存器，从 vm->reg[] 加载全部 BPF 寄存器，
// 执行入口 safepoint 检查。
// ---------------------------------------------------------------------------

size_t X86Emitter::emit_prologue() {
    // 保存 callee-saved 寄存器
    push_rbp();                               // push rbp
    push_reg(X86::RBX);                       // push rbx
    push_reg(X86::R12);                       // push r12
    push_reg(X86::R13);                       // push r13
    push_reg(X86::R14);                       // push r14
    push_reg(X86::R15);                       // push r15
    // 对齐栈到 16 字节（6 pushes + return addr = 56 bytes, +8 = 64）
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);  // sub rsp, 8

    // RBP = vm* 指针
    mov_r64(X86::RBP, X86::RDI);             // mov rbp, rdi

    // 从 vm->reg[] 加载全部 11 个 BPF 寄存器
    for (int i = 0; i < 11; i++) {
        load_r64(BPF_REG_MAP[i], (int32_t)(off_reg_ + i * 8));
    }

    // jmp .entry（走入口 safepoint）
    jmp_rel32();
    size_t entry_jmp_offset = size() - 5;

    // .vm_exit: 恢复 callee-saved 并返回
    vm_exit_offset = size();
    emit8(0x48); emit8(0x83); emit8(0xC4); emit8(0x08);  // add rsp, 8
    pop_reg(X86::R15);                        // pop r15
    pop_reg(X86::R14);                        // pop r14
    pop_reg(X86::R13);                        // pop r13
    pop_reg(X86::R12);                        // pop r12
    pop_reg(X86::RBX);                        // pop rbx
    pop_rbp();                                // pop rbp
    emit8(0xC3);                              // ret

    // .flush_and_exit: 将全部 BPF 寄存器写回 vm->reg[]，然后跳到 .vm_exit
    //
    // 到达此处的路径要求：x86 中的 BPF 寄存器值是有效的。
    // 典型场景：memory abort（TLB miss 后 null 返回、bounds check 失败等）。
    // 对于 helper CALL 后的路径（safepoint 等），caller-saved 寄存器已被踩掉，
    // 这些路径必须在 CALL 前 flush，然后直接跳 vm_exit，不经过此处。
    size_t flush_and_exit_offset = size();
    for (int i = 0; i < 10; i++) {
        store_r64((int32_t)(off_reg_ + i * 8), BPF_REG_MAP[i]);
    }
    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(jmp_off, vm_exit_offset);

    // .entry_fast: 跨函数直跳第二入口（caller 用 call r11 进入）。跳过 .entry safepoint
    //   （caller 已做 flags-check），且不从 vm->reg[] 加载——caller 在 call r11 前已把
    //   r1-r5(参数)、r6-r9(callee-saved)、r10(frame_base 由 push_frame 设入 R15) 备好，
    //   r0 为死值，RBP=vm* 跨 call 保留。故无 flush/reload、无 mov rbp,rdi（RDI=r3 会踩参数）。
    entry_fast_offset = size();
    push_rbp();
    push_reg(X86::RBX);
    push_reg(X86::R12);
    push_reg(X86::R13);
    push_reg(X86::R14);
    push_reg(X86::R15);
    emit8(0x48); emit8(0x83); emit8(0xEC); emit8(0x08);  // sub rsp, 8
    // RBP 已是 vm*（跨 call 保留），无 mov rbp,rdi、无 vm->reg[] load（见上注释）。
    jmp_rel32();
    size_t fast_jmp_offset = size() - 5;

    // .entry: 入口 safepoint
    size_t entry_offset = size();
    patch_branch_uncond(entry_jmp_offset, entry_offset);

    // Safepoint at entry: 必须先 flush 所有寄存器（信号处理器可能读取）
    flush_to_vm();
    mov_r64(X86::RDI, X86::RBP);             // mov rdi, rbp
    call_helper(helpers_->safepoint);
    test_eax_eax();
    // Safepoint 失败 -> 直接跳 vm_exit（不走 flush_and_exit，因为 flush 已做过，
    // 而且信号处理器可能已修改 vm->reg[]，不能再用 x86 寄存器覆盖）
    size_t sp_jne = size();
    emit8(0x0F); emit8(0x85); emit32(0);     // JNE .vm_exit
    patch_branch_cond(sp_jne, vm_exit_offset);

    // Safepoint 返回后 reload caller-saved（callee-saved 自动存活）
    reload_caller_saved();

    // 第一条 BPF 指令从这里开始。entry_fast 直接到此。
    patch_branch_uncond(fast_jmp_offset, size());

    return flush_and_exit_offset;
}

// ---------------------------------------------------------------------------
// Safepoint (at loop back-edge targets)
//
// 循环回边处插入安全点，让 VM 有机会处理信号和检查中止标志。
// ---------------------------------------------------------------------------

void X86Emitter::emit_safepoint(uint32_t loop_body_size, uint64_t insn_gpa) {
    if (insn_count_enabled_) {
        // --- 指令计数递增 ---
        // mov rax, qword [rbp + off_insn_count_]
        emit8(0x48); emit8(0x8B); emit8(modrm(2, X86::RAX, X86::RBP));
        emit32((uint32_t)off_insn_count_);
        // add rax, loop_body_size
        add64_imm((int32_t)loop_body_size);
        // mov qword [rbp + off_insn_count_], rax
        emit8(0x48); emit8(0x89); emit8(modrm(2, X86::RAX, X86::RBP));
        emit32((uint32_t)off_insn_count_);

        if (budget_enabled_) {
            // --- 预算检查 ---
            // cmp rax, qword [rbp + off_insn_limit_]
            emit8(0x48); emit8(0x3B); emit8(modrm(2, X86::RAX, X86::RBP));
            emit32((uint32_t)off_insn_limit_);
            size_t budget_ok_jb = size();
            emit8(0x0F); emit8(0x82); emit32(0);  // JB .check_flags (count < limit)

            // .budget_exceeded: lock or dword [rbp + off_flags_], VM_BUDGET_EXCEEDED(0x10)
            emit8(0xF0); emit8(0x83); emit8(modrm(2, 1, X86::RBP));
            emit32((uint32_t)off_flags_);
            emit8(0x10);
            // jmp .vm_exit
            size_t budget_exit_jmp = size();
            emit8(0xE9); emit32(0);
            patch_branch_uncond(budget_exit_jmp, vm_exit_offset);

            // .check_flags:
            patch_branch_cond(budget_ok_jb, size());
        }
    }

    // 快速路径：cmp dword [rbp + off_flags_], 0
    emit8(0x83); emit8(modrm(2, 7, X86::RBP)); emit32((uint32_t)off_flags_);
    emit8(0x00);
    size_t flags_jnz = size();
    emit8(0x0F); emit8(0x85); emit32(0);     // JNZ .slow_safepoint

    // 快速路径：无异常也无待处理信号，跳过
    size_t fast_jmp = size();
    emit8(0xE9); emit32(0);                  // JMP .done

    // .slow_safepoint: flush 所有寄存器 + 调用 helper
    size_t slow_start = size();
    patch_branch_cond(flags_jnz, slow_start);

    flush_to_vm();

    // 写当前 guest pc 到 vm->pc。JIT 的"寄存器驻留纯执行段"不维护 vm->pc，
    // 但 safepoint 的 slow path 会调用 helper_safepoint -> handle_signals，后者用
    // vm->pc 作为信号返回帧的返回地址。若不写回，vm->pc 会停在最后一次
    // emit_call_syscall 的 stale 值上，导致信号处理返回后回到错误的 pc（如重复
    // 执行一条 syscall 形式的 call 指令）。insn_gpa 是本 safepoint 所在 BPF 指令
    // （循环头）的 guest 地址，即信号返回后应当恢复执行的位置。
    // RAX 作写 pc 的专用 scratch（非参数寄存器；对应 aarch64 版用 X2）。
    mov_rax_imm64(insn_gpa);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);  // mov [rbp+off_pc], rax

    mov_r64(X86::RDI, X86::RBP);
    call_helper(helpers_->safepoint);
    test_eax_eax();
    size_t sp_jne = size();
    emit8(0x0F); emit8(0x85); emit32(0);     // JNE .vm_exit
    patch_branch_cond(sp_jne, vm_exit_offset);
    reload_caller_saved();

    // .done
    size_t done = size();
    patch_branch_uncond(fast_jmp, done);
}

#endif // __x86_64__
