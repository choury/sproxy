//
// x86_emitter.cpp — x86_64-specific JIT code emission implementation.
//
// 寄存器分配方案详见 x86_emitter.h 顶部注释。
// 核心思路：全部 11 个 BPF 寄存器都映射到 x86 物理寄存器，
// ALU/分支指令在纯寄存器之间操作，只在调用 helper 函数时
// 才与 vm->reg[] 内存交互。
//

#include "x86_emitter.h"

#include <cstdint>
#include <cstring>

#if defined(__x86_64__)

#include "insn.h"

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

        // sign-extend RAX → RDX:RAX (cqo/cdq)
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
        // patch 溢出路径的 JMP → .done
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

    // Compute TLB index into R11: ((addr >> 20) & (TLB_SIZE-1)) * sizeof(TlbEntry)
    // mov r11, rax
    emit8(0x49); emit8(0x89); emit8(0xC3);
    // shr r11, 20
    emit8(0x49); emit8(0xC1); emit8(0xEB); emit8(20);
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
    call_helper(is_write ? helpers_.mmu_w : helpers_.mmu);

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
    // Patch miss jumps → .slow
    for (size_t off : ctx.miss_jumps) {
        patch_branch_cond(off, ctx.slow_start);
    }
    // Patch fast-path JMP → .done
    patch_branch_uncond(ctx.done_jmp, ctx.done_offset);
    // Record abort jumps for later patching to .vm_exit
    for (size_t off : ctx.abort_jumps) {
        abort_patches.push_back({off, bpf_index});
    }
}

// ---------------------------------------------------------------------------
// ALU (unified for ALU64 and ALU32)
//
// 操作流程：load_bpf(dst→RAX), load_bpf(src→RCX), ALU, store_bpf(dst←RAX)
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
                                      const bpf_insn* entry_pc) {
    // 完整 flush 所有 BPF 寄存器到 vm->reg[]
    flush_to_vm();

    // 保存当前 pc 到 vm->pc
    const bpf_insn* insn_host = entry_pc + current_index;
    mov_rax_imm64((uint64_t)(uintptr_t)insn_host);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);  // mov [rbp+off_pc], rax

    // 调用 helper_do_syscall(vm*, call_id)
    mov_r64(X86::RDI, X86::RBP);                              // mov rdi, rbp
    emit8(0xBE); emit32((uint32_t)insn->imm);                 // mov esi, call_id
    call_helper(helpers_.do_syscall);

    // 检查返回值
    test_al_al();
    size_t jz_off = size();
    emit8(0x0F); emit8(0x84); emit32(0);  // JZ .vm_exit
    patch_branch_cond(jz_off, vm_exit_offset);

    // 完整 reload 所有 BPF 寄存器（syscall 可能改了任意寄存器）
    reload_from_vm();
}

// ---------------------------------------------------------------------------
// CALL BPF-to-BPF (src_reg==1)
//
// 目标函数需要从 vm->reg[] 读取参数，所以需要完整 flush。
// 编译完成后跳回 vm_exit，让 step() 循环重新编译目标函数。
// ---------------------------------------------------------------------------

void X86Emitter::emit_call_bpf(const bpf_insn* insn, int current_index,
                                  uint64_t ret_gpa,
                                  const bpf_insn* entry_pc) {
    // flush_to_vm 已经将所有寄存器写回 vm->reg[]，
    // 后续不能再走 flush_and_exit（会把被 CALL 踩掉的垃圾值写回），
    // 所有跳转都直接到 vm_exit。
    flush_to_vm();

    mov_r64(X86::RDI, X86::RBP);                              // mov rdi, rbp
    emit8(0x48); emit8(0xBE); emit64(ret_gpa);                // mov rsi, ret_gpa
    call_helper(helpers_.push_frame);
    test_al_al();
    // push_frame 失败 → 直接跳 vm_exit
    size_t jz_off = size();
    emit8(0x0F); emit8(0x84); emit32(0);                      // JZ .vm_exit
    patch_branch_cond(jz_off, vm_exit_offset);

    // 设置 pc 指向被调函数
    const bpf_insn* callee_pc = entry_pc + current_index + 1 + insn->imm;
    mov_rax_imm64((uint64_t)(uintptr_t)callee_pc);
    emit8(0x48); emit8(0x89); emit8(0x85); emit32((uint32_t)off_pc_);

    // 跳到 vm_exit（让 step() 循环重新进入 JIT）
    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(jmp_off, vm_exit_offset);
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
    call_helper(helpers_.call_indirect);
    // helper_call_indirect 执行后总是需要退出 JIT（pc 已改变或 VM 被终止）
    // 直接跳 vm_exit（flush 已经做过了）
    size_t jmp_off = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(jmp_off, vm_exit_offset);
}

// ---------------------------------------------------------------------------
// EXIT
// ---------------------------------------------------------------------------

void X86Emitter::emit_exit() {
    flush_to_vm();

    mov_r64(X86::RDI, X86::RBP);                              // mov rdi, rbp
    call_helper(helpers_.pop_frame);

    test_rax_rax();
    size_t has_ret_jcc = size();
    emit8(0x0F); emit8(0x85); emit32(0);  // JNZ .has_ret_addr

    // Stack bottom: set VM_EXITED flag
    // lock or dword [rbp + off_flags], VM_EXITED(1)
    emit8(0xF0); emit8(0x83); emit8(0x8D);
    emit32((uint32_t)off_flags_);
    emit8(0x01);
    size_t stack_bottom_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(stack_bottom_jmp, vm_exit_offset);

    // .has_ret_addr: return to caller
    size_t has_ret_target = size();
    patch_branch_cond(has_ret_jcc, has_ret_target);

    mov_r64(X86::RDI, X86::RBP);
    mov_r64(X86::RSI, X86::RAX);                              // mov rsi, rax (return addr)
    call_helper(helpers_.return_to_caller);

    size_t exit_jmp = size();
    emit8(0xE9); emit32(0);
    patch_branch_uncond(exit_jmp, vm_exit_offset);
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

    // jmp .entry
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

    // .entry: 入口 safepoint
    size_t entry_offset = size();
    patch_branch_uncond(entry_jmp_offset, entry_offset);

    // Safepoint at entry: 必须先 flush 所有寄存器（信号处理器可能读取）
    flush_to_vm();
    mov_r64(X86::RDI, X86::RBP);             // mov rdi, rbp
    call_helper(helpers_.safepoint);
    test_eax_eax();
    // Safepoint 失败 → 直接跳 vm_exit（不走 flush_and_exit，因为 flush 已做过，
    // 而且信号处理器可能已修改 vm->reg[]，不能再用 x86 寄存器覆盖）
    size_t sp_jne = size();
    emit8(0x0F); emit8(0x85); emit32(0);     // JNE .vm_exit
    patch_branch_cond(sp_jne, vm_exit_offset);

    // Safepoint 返回后 reload caller-saved（callee-saved 自动存活）
    reload_caller_saved();

    return flush_and_exit_offset;
}

// ---------------------------------------------------------------------------
// Safepoint (at loop back-edge targets)
//
// 循环回边处插入安全点，让 VM 有机会处理信号和检查中止标志。
// ---------------------------------------------------------------------------

void X86Emitter::emit_safepoint(uint32_t loop_body_size) {
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
    mov_r64(X86::RDI, X86::RBP);
    call_helper(helpers_.safepoint);
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
