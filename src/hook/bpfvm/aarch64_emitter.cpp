//
// aarch64_emitter.cpp — AArch64-specific JIT code emission implementation.
//
// 寄存器分配方案详见 aarch64_emitter.h 顶部注释。
// 编码常量经 V8 constants-arm64.h 交叉验证。
//

#include "aarch64_emitter.h"
#include "insn.h"

#include <cstring>

#if defined(__aarch64__)

using namespace ARM;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void AArch64Emitter::emit_insn(uint32_t insn) {
    buf_.push_back(insn & 0xFF);
    buf_.push_back((insn >> 8) & 0xFF);
    buf_.push_back((insn >> 16) & 0xFF);
    buf_.push_back((insn >> 24) & 0xFF);
}

static inline uint32_t rd(uint8_t r) { return r & 0x1F; }

// ---------------------------------------------------------------------------
// MOVZ / MOVK  (hw=shift/16, imm16 at bits 20:5)
// MOVZ_x=0xD2800000 MOVK_x=0xF2800000  MOVZ_w=0x52800000 MOVK_w=0x72800000
// ---------------------------------------------------------------------------

void AArch64Emitter::movz(uint8_t dst, uint16_t imm, int shift, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    uint32_t hw = (shift >= 16) ? (uint32_t)(shift / 16) : 0u;
    emit_insn((sf << 31) | (1u << 30) | (0x25u << 23) | (hw << 21) | ((uint32_t)imm << 5) | rd(dst));
}
void AArch64Emitter::movk(uint8_t dst, uint16_t imm, int shift, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    uint32_t hw = (shift >= 16) ? (uint32_t)(shift / 16) : 0u;
    emit_insn((sf << 31) | (1u << 30) | (1u << 29) | (0x25u << 23) | (hw << 21) | ((uint32_t)imm << 5) | rd(dst));
}
void AArch64Emitter::mov_imm(uint8_t dst, uint64_t val, bool is_64) {
    const int N = is_64 ? 4 : 2;
    uint16_t p[4] = {
        (uint16_t)(val & 0xFFFF), (uint16_t)((val >> 16) & 0xFFFF),
        (uint16_t)((val >> 32) & 0xFFFF), (uint16_t)((val >> 48) & 0xFFFF)
    };
    // nz = non-zero chunks, nf = non-0xFFFF chunks
    int nz = 0, nf = 0;
    for (int i = 0; i < N; i++) {
        if (p[i] != 0) nz++;
        if (p[i] != 0xFFFF) nf++;
    }
    // MOVZ needs max(nz,1) insns, MOVN needs max(nf,1) insns — pick cheaper
    bool use_movn = nf < nz;
    bool first = true;
    if (use_movn) {
        uint32_t base = is_64 ? 0x92800000u : 0x12800000u;
        for (int i = 0; i < N; i++) {
            if (p[i] != 0xFFFF) {
                if (first) {
                    emit_insn(base | ((uint32_t)i << 21) | ((uint32_t)(~p[i] & 0xFFFF) << 5) | rd(dst));
                    first = false;
                } else {
                    movk(dst, p[i], i * 16, is_64);
                }
            }
        }
        if (first) emit_insn(base | rd(dst)); // all 0xFFFF → MOVN #0
    } else {
        for (int i = 0; i < N; i++) {
            if (p[i]) {
                if (first) { movz(dst, p[i], i * 16, is_64); first = false; }
                else movk(dst, p[i], i * 16, is_64);
            }
        }
        if (first) movz(dst, 0, 0, is_64); // all zero → MOVZ #0
    }
}

// ---------------------------------------------------------------------------
// MOV register: ORR Rd, XZR, Rm
// ---------------------------------------------------------------------------

void AArch64Emitter::mov_reg(uint8_t dst, uint8_t src, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (1u << 29) | (0x0Au << 24) | ((uint32_t)src << 16) | (0x1Fu << 5) | rd(dst));
}

// ---------------------------------------------------------------------------
// ALU register-register  (sf opc 01011 00 0 Rm 000000 Rn Rd)
// ADD_x=0x8B SUB_x=0xCB AND_x=0x8A ORR_x=0xAA EOR_x=0xCA
// ---------------------------------------------------------------------------

void AArch64Emitter::add_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (0x0Bu << 24) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::sub_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (1u << 30) | (0x0Bu << 24) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::and_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (0x0Au << 24) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::orr_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (1u << 29) | (0x0Au << 24) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::eor_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (1u << 30) | (0x0Au << 24) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::mul_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (0x1Bu << 24) | ((uint32_t)m << 16) | (0x1Fu << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::msub_reg(uint8_t d, uint8_t n, uint8_t m, uint8_t a, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    emit_insn((sf << 31) | (0x1Bu << 24) | ((uint32_t)m << 16) | (1u << 15)
              | ((uint32_t)a << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::udiv_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0x9AC00800u : 0x1AC00800u) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::sdiv_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0x9AC00C00u : 0x1AC00C00u) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::neg_reg(uint8_t d, uint8_t s, bool is_64) { sub_reg(d, 31, s, is_64); }
void AArch64Emitter::lsl_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0x9AC02000u : 0x1AC02000u) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::lsr_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0x9AC02400u : 0x1AC02400u) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::asr_reg(uint8_t d, uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0x9AC02800u : 0x1AC02800u) | ((uint32_t)m << 16) | ((uint32_t)n << 5) | rd(d));
}

// ---------------------------------------------------------------------------
// ALU immediate  ADD_i_x=0x91000000 SUB_i_x=0xD1000000
// ---------------------------------------------------------------------------

void AArch64Emitter::add_imm(uint8_t d, uint8_t n, int64_t imm, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    if (imm >= 0 && imm <= 4095) {
        emit_insn((sf << 31) | (0x11u << 24) | ((uint32_t)imm << 10) | ((uint32_t)n << 5) | rd(d));
    } else if (imm < 0 && imm >= -4095) {
        emit_insn((sf << 31) | (1u << 30) | (0x11u << 24) | ((uint32_t)(-imm) << 10) | ((uint32_t)n << 5) | rd(d));
    } else {
        mov_imm(X2, (uint64_t)imm, is_64);
        add_reg(d, n, X2, is_64);
    }
}
void AArch64Emitter::sub_imm(uint8_t d, uint8_t n, int64_t imm, bool is_64) {
    if (imm >= -4095 && imm <= 4095) add_imm(d, n, -imm, is_64);
    else { mov_imm(X2, (uint64_t)imm, is_64); sub_reg(d, n, X2, is_64); }
}
void AArch64Emitter::and_imm(uint8_t d, uint8_t n, uint64_t imm, bool is_64) {
    mov_imm(X2, imm, is_64); and_reg(d, n, X2, is_64);
}
void AArch64Emitter::orr_imm(uint8_t d, uint8_t n, uint64_t imm, bool is_64) {
    mov_imm(X2, imm, is_64); orr_reg(d, n, X2, is_64);
}
void AArch64Emitter::eor_imm(uint8_t d, uint8_t n, uint64_t imm, bool is_64) {
    mov_imm(X2, imm, is_64); eor_reg(d, n, X2, is_64);
}

// ---------------------------------------------------------------------------
// Shift immediate  UBFM/SBFM  (immr at 21:16, imms at 15:10)
// LSL = UBFM Rd,Rn,#(-shift MOD 64),#(63-shift)
// LSR = UBFM Rd,Rn,#shift,#63
// ASR = SBFM Rd,Rn,#shift,#63
// ---------------------------------------------------------------------------

void AArch64Emitter::lsl_imm(uint8_t d, uint8_t n, uint8_t c, bool is_64) {
    uint32_t bits = is_64 ? 64u : 32u;
    uint32_t immr = (-c) & (bits - 1);
    uint32_t imms = bits - 1 - c;
    emit_insn((is_64 ? 0xD3400000u : 0x53000000u) | (immr << 16) | (imms << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::lsr_imm(uint8_t d, uint8_t n, uint8_t c, bool is_64) {
    uint32_t imms = is_64 ? 63u : 31u;
    emit_insn((is_64 ? 0xD3400000u : 0x53000000u) | ((uint32_t)c << 16) | (imms << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::asr_imm(uint8_t d, uint8_t n, uint8_t c, bool is_64) {
    uint32_t imms = is_64 ? 63u : 31u;
    emit_insn((is_64 ? 0x93400000u : 0x13000000u) | ((uint32_t)c << 16) | (imms << 10) | ((uint32_t)n << 5) | rd(d));
}

// ---------------------------------------------------------------------------
// CMP / TST
// ---------------------------------------------------------------------------

void AArch64Emitter::cmp_reg(uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0xEB00001Fu : 0x6B00001Fu) | ((uint32_t)m << 16) | ((uint32_t)n << 5));
}
void AArch64Emitter::cmp_imm(uint8_t n, int64_t imm, bool is_64) {
    uint32_t sf = is_64 ? 1u : 0u;
    if (imm >= 0 && imm <= 4095) {
        emit_insn((sf << 31) | (1u << 30) | (1u << 29) | (0x11u << 24) | ((uint32_t)imm << 10) | ((uint32_t)n << 5) | 0x1Fu);
    } else {
        mov_imm(X2, (uint64_t)imm, is_64);
        cmp_reg(n, X2, is_64);
    }
}
void AArch64Emitter::tst_reg(uint8_t n, uint8_t m, bool is_64) {
    emit_insn((is_64 ? 0xEA00001Fu : 0x6A00001Fu) | ((uint32_t)m << 16) | ((uint32_t)n << 5));
}

// ---------------------------------------------------------------------------
// Branches
// ---------------------------------------------------------------------------

void AArch64Emitter::b_cond(uint8_t cond) { emit_insn(0x54000000u | (uint32_t)cond); }
void AArch64Emitter::b_uncond() { emit_insn(0x14000000u); }
void AArch64Emitter::blr(uint8_t reg) { emit_insn(0xD63F0000u | ((uint32_t)reg << 5)); }
void AArch64Emitter::ret() { emit_insn(0xD65F03C0u); }
void AArch64Emitter::cbz(uint8_t reg, bool is_64) {
    emit_insn((is_64 ? 0xB4000000u : 0x34000000u) | rd(reg));
}
void AArch64Emitter::cbnz(uint8_t reg, bool is_64) {
    emit_insn((is_64 ? 0xB5000000u : 0x35000000u) | rd(reg));
}

// ---------------------------------------------------------------------------
// Load/Store unsigned offset
// ---------------------------------------------------------------------------

void AArch64Emitter::ldr_imm(uint8_t t, uint8_t n, int32_t off, bool is_64) {
    uint32_t scale = is_64 ? 8u : 4u;
    if (off >= 0 && (off % scale) == 0 && (uint32_t)(off / scale) <= 0xFFF) {
        emit_insn((is_64 ? 0xF9400000u : 0xB9400000u) | ((uint32_t)(off / scale) << 10) | ((uint32_t)n << 5) | rd(t));
        return;
    }
    // Fallback: compute addr in X1
    if (off != 0) add_imm(X1, n, off, true);
    emit_insn((is_64 ? 0xF9400000u : 0xB9400000u) | ((off != 0 ? (uint32_t)X1 : (uint32_t)n) << 5) | rd(t));
}
void AArch64Emitter::str_imm(uint8_t t, uint8_t n, int32_t off, bool is_64) {
    uint32_t scale = is_64 ? 8u : 4u;
    if (off >= 0 && (off % scale) == 0 && (uint32_t)(off / scale) <= 0xFFF) {
        emit_insn((is_64 ? 0xF9000000u : 0xB9000000u) | ((uint32_t)(off / scale) << 10) | ((uint32_t)n << 5) | rd(t));
        return;
    }
    if (off != 0) add_imm(X1, n, off, true);
    emit_insn((is_64 ? 0xF9000000u : 0xB9000000u) | ((off != 0 ? (uint32_t)X1 : (uint32_t)n) << 5) | rd(t));
}
void AArch64Emitter::ldrsw(uint8_t t, uint8_t n, int32_t off) {
    if (off >= 0 && (off % 4) == 0 && (uint32_t)(off / 4) <= 0xFFF) {
        emit_insn(0xB9800000u | ((uint32_t)(off / 4) << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(0xB9800000u | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::ldrsh(uint8_t t, uint8_t n, int32_t off, bool is_64) {
    uint32_t base = is_64 ? 0x79800000u : 0x79C00000u;
    if (off >= 0 && (off % 2) == 0 && (uint32_t)(off / 2) <= 0xFFF) {
        emit_insn(base | ((uint32_t)(off / 2) << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(base | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::ldrsb(uint8_t t, uint8_t n, int32_t off, bool is_64) {
    uint32_t base = is_64 ? 0x39800000u : 0x39C00000u;
    if (off >= 0 && (uint32_t)off <= 0xFFF) {
        emit_insn(base | ((uint32_t)off << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(base | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::ldrh(uint8_t t, uint8_t n, int32_t off) {
    if (off >= 0 && (off % 2) == 0 && (uint32_t)(off / 2) <= 0xFFF) {
        emit_insn(0x79400000u | ((uint32_t)(off / 2) << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(0x79400000u | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::ldrb(uint8_t t, uint8_t n, int32_t off) {
    if (off >= 0 && (uint32_t)off <= 0xFFF) {
        emit_insn(0x39400000u | ((uint32_t)off << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(0x39400000u | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::strh(uint8_t t, uint8_t n, int32_t off) {
    if (off >= 0 && (off % 2) == 0 && (uint32_t)(off / 2) <= 0xFFF) {
        emit_insn(0x79000000u | ((uint32_t)(off / 2) << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(0x79000000u | ((uint32_t)X1 << 5) | rd(t));
}
void AArch64Emitter::strb(uint8_t t, uint8_t n, int32_t off) {
    if (off >= 0 && (uint32_t)off <= 0xFFF) {
        emit_insn(0x39000000u | ((uint32_t)off << 10) | ((uint32_t)n << 5) | rd(t)); return;
    }
    add_imm(X1, n, off, true); emit_insn(0x39000000u | ((uint32_t)X1 << 5) | rd(t));
}
// STP/LDP signed offset  (imm7 at bits 21:15, scaled by 8 for 64-bit)
void AArch64Emitter::stp(uint8_t t1, uint8_t t2, uint8_t n, int32_t off, bool is_64) {
    uint32_t imm7 = (uint32_t)((int64_t)off / (is_64 ? 8 : 4)) & 0x7F;
    emit_insn((is_64 ? 0xA9000000u : 0x29000000u) | (imm7 << 15) | ((uint32_t)t2 << 10) | ((uint32_t)n << 5) | rd(t1));
}
void AArch64Emitter::ldp(uint8_t t1, uint8_t t2, uint8_t n, int32_t off, bool is_64) {
    uint32_t imm7 = (uint32_t)((int64_t)off / (is_64 ? 8 : 4)) & 0x7F;
    emit_insn((is_64 ? 0xA9400000u : 0x29400000u) | (imm7 << 15) | ((uint32_t)t2 << 10) | ((uint32_t)n << 5) | rd(t1));
}

// ---------------------------------------------------------------------------
// Sign extension  SBFM: immr at 21:16, imms at 15:10
// SXTB: immr=0,imms=7  SXTH: immr=0,imms=15  SXTW: immr=0,imms=31
// ---------------------------------------------------------------------------

void AArch64Emitter::sxtb(uint8_t d, uint8_t n, bool is_64) {
    emit_insn((is_64 ? 0x93400000u : 0x13000000u) | (7u << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::sxth(uint8_t d, uint8_t n, bool is_64) {
    emit_insn((is_64 ? 0x93400000u : 0x13000000u) | (15u << 10) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::sxtw(uint8_t d, uint8_t n) {
    emit_insn(0x93400000u | (31u << 10) | ((uint32_t)n << 5) | rd(d));
}

// ---------------------------------------------------------------------------
// Byte swap  REV=0xDAC00C00 REV32=0x5AC00800 REV16=0xDAC00400/0x5AC00400
// ---------------------------------------------------------------------------

void AArch64Emitter::rev16(uint8_t d, uint8_t n, bool is_64) {
    emit_insn((is_64 ? 0xDAC00400u : 0x5AC00400u) | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::rev32(uint8_t d, uint8_t n) {
    emit_insn(0x5AC00800u | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::rev64(uint8_t d, uint8_t n) {
    emit_insn(0xDAC00C00u | ((uint32_t)n << 5) | rd(d));
}
void AArch64Emitter::dmb() { emit_insn(0xD5033BBFu); }

// ---------------------------------------------------------------------------
// BPF register access  (all in physical regs, load/store are just mov or nop)
// ---------------------------------------------------------------------------

void AArch64Emitter::load_bpf(uint8_t bpf_r, uint8_t dst) {
    uint8_t mapped = BPF_REG_MAP[bpf_r];
    if (mapped != dst) mov_reg(dst, mapped, true);
}
void AArch64Emitter::store_bpf(uint8_t bpf_r, uint8_t src, bool is_64) {
    uint8_t mapped = BPF_REG_MAP[bpf_r];
    if (!is_64) mov_reg(mapped, src, false);      // 32-bit mov zero-extends
    else if (mapped != src) mov_reg(mapped, src, true);
}

// ---------------------------------------------------------------------------
// Flush / reload
// ---------------------------------------------------------------------------

void AArch64Emitter::flush_to_vm() {
    for (int i = 0; i < 10; i++) str_imm(BPF_REG_MAP[i], X28, (int32_t)(off_reg_ + i * 8), true);
}
void AArch64Emitter::reload_from_vm() {
    for (int i = 0; i < 10; i++) ldr_imm(BPF_REG_MAP[i], X28, (int32_t)(off_reg_ + i * 8), true);
}
void AArch64Emitter::reload_caller_saved() {
    for (int i = 0; i < BPF_CALLER_SAVED_COUNT; i++)
        ldr_imm(BPF_CALLER_SAVED_ARM[i], X28, (int32_t)(off_reg_ + i * 8), true);
}
void AArch64Emitter::spill_caller_saved() {
    // SUB SP, #48; STP pairs
    add_imm(SP, SP, -48, true);
    stp(X9, X10, SP, 0, true);
    stp(X11, X12, SP, 16, true);
    stp(X13, X14, SP, 32, true);
}
void AArch64Emitter::restore_caller_saved() {
    ldp(X9, X10, SP, 0, true);
    ldp(X11, X12, SP, 16, true);
    ldp(X13, X14, SP, 32, true);
    add_imm(SP, SP, 48, true);
}

// ---------------------------------------------------------------------------
// Helper call: mov_imm X15, addr; BLR X15
// ---------------------------------------------------------------------------

void AArch64Emitter::call_helper(void* addr) {
    mov_imm(X15, (uint64_t)(uintptr_t)addr, true);
    blr(X15);
}

// ---------------------------------------------------------------------------
// Patching  (B.cond/CBZ/CBNZ: imm19 at bits 23:5; B: imm26 at bits 25:0)
// ---------------------------------------------------------------------------

void AArch64Emitter::patch_branch_cond(size_t off, size_t target) {
    int32_t rel = (int32_t)(target - off) / 4;
    uint32_t insn; memcpy(&insn, data() + off, 4);
    insn = (insn & 0xFF00001Fu) | (((uint32_t)rel & 0x7FFFFu) << 5);
    memcpy(data() + off, &insn, 4);
}
void AArch64Emitter::patch_branch_uncond(size_t off, size_t target) {
    int32_t rel = (int32_t)(target - off) / 4;
    uint32_t insn; memcpy(&insn, data() + off, 4);
    insn = (insn & 0xFC000000u) | ((uint32_t)rel & 0x3FFFFFFu);
    memcpy(data() + off, &insn, 4);
}

// ---------------------------------------------------------------------------
// TLB inline fast path + slow path
// ---------------------------------------------------------------------------

MemAccessContext AArch64Emitter::begin_mem_access(uint8_t base_reg, int16_t offset,
                                                   int access_size, bool is_write) {
    MemAccessContext ctx{};

    // X0 = guest address
    if (base_reg != X0) mov_reg(X0, base_reg, true);
    if (offset != 0) add_imm(X0, X0, offset, true);

    // X15 = TLB entry pointer = vm_ptr + off_tlb + ((addr>>20) & (TLB_SIZE-1)) * sizeof(TlbEntry)
    lsr_imm(X15, X0, 20, true);
    and_imm(X15, X15, TLB_SIZE - 1, true);
    lsl_imm(X15, X15, __builtin_ctz(sizeof(TlbEntry)), true);
    add_reg(X15, X15, X28, true);
    add_imm(X15, X15, (int64_t)off_tlb_, true);

    constexpr int32_t off_gb = (int32_t)offsetof(TlbEntry, guest_base);
    constexpr int32_t off_ge = (int32_t)offsetof(TlbEntry, guest_end);
    constexpr int32_t off_hb = (int32_t)offsetof(TlbEntry, host_base);
    constexpr int32_t off_fl = (int32_t)offsetof(TlbEntry, flags);
    constexpr int32_t off_cw = (int32_t)offsetof(TlbEntry, cow);

    // Bounds check 1: addr >= guest_base
    ldr_imm(X1, X15, off_gb, true);
    cmp_reg(X0, X1, true);
    ctx.miss_jumps.push_back(size());
    emit_insn(0x54000000u | ARMCond::CC); // B.cc (addr < base → slow)

    // Bounds check 2: addr + size <= guest_end
    add_imm(X2, X0, access_size, true);
    ldr_imm(X1, X15, off_ge, true);
    cmp_reg(X2, X1, true);
    ctx.miss_jumps.push_back(size());
    emit_insn(0x54000000u | ARMCond::HI); // B.hi (end > guest_end → slow)

    if (is_write) {
        // flags & PF_W
        ldr_imm(X1, X15, off_fl, false); // W load
        mov_imm(X2, 2, false);            // PF_W = 0x2
        tst_reg(X1, X2, false);
        ctx.miss_jumps.push_back(size());
        emit_insn(0x54000000u | ARMCond::EQ); // B.eq → slow

        // !cow
        ldrb(X1, X15, off_cw);
        ctx.miss_jumps.push_back(size());
        cbnz(X1, true);
    }

    // TLB hit: host_ptr = host_base + (addr - guest_base)
    ldr_imm(X1, X15, off_gb, true);
    sub_reg(X0, X0, X1, true);
    ldr_imm(X1, X15, off_hb, true);
    add_reg(X0, X0, X1, true);

    // JMP .done
    ctx.done_jmp = size();
    b_uncond();

    // .slow
    ctx.slow_start = size();
    spill_caller_saved();
    mov_reg(X1, X0, true);           // arg2 = guest addr
    mov_reg(X0, X28, true);          // arg1 = vm*
    mov_imm(X2, (uint64_t)access_size, true); // arg3 = size
    call_helper(is_write ? helpers_.mmu_w : helpers_.mmu);
    restore_caller_saved();
    cbz(X0, true);                   // null → .vm_exit (recorded as abort)
    ctx.abort_jumps.push_back(size() - 4);

    // .done
    ctx.done_offset = size();
    return ctx;
}

void AArch64Emitter::finish_mem_access(MemAccessContext& ctx,
                                          std::vector<AbortPatchInfo>& abort_patches, int bpf_index) {
    for (size_t off : ctx.miss_jumps) patch_branch_cond(off, ctx.slow_start);
    patch_branch_uncond(ctx.done_jmp, ctx.done_offset);
    for (size_t off : ctx.abort_jumps)
        abort_patches.push_back({off, bpf_index});
}

// ---------------------------------------------------------------------------
// ALU
// ---------------------------------------------------------------------------

bool AArch64Emitter::emit_alu(const bpf_insn* insn, bool is_64) {
    bool is_x = (insn->code & 0x08) == BPF_X;
    uint8_t op = insn->code & 0xf0;

    auto load_dst = [&]() { load_bpf(insn->dst_reg, X0); };
    auto load_src = [&]() { load_bpf(insn->src_reg, X1); };
    auto store_dst = [&]() { store_bpf(insn->dst_reg, X0, is_64); };

    // MOV (off == 0)
    if (op == BPF_MOV && insn->off == 0) {
        if (is_64 && is_x && insn->dst_reg == insn->src_reg) return true;
        if (is_x) {
            uint8_t sd = BPF_REG_MAP[insn->dst_reg], ss = BPF_REG_MAP[insn->src_reg];
            if (!is_64) mov_reg(sd, ss, false);
            else if (sd != ss) mov_reg(sd, ss, true);
        } else {
            uint8_t sd = BPF_REG_MAP[insn->dst_reg];
            if (is_64) { mov_imm(X0, (uint64_t)(int64_t)insn->imm, true); mov_reg(sd, X0, true); }
            else { mov_imm(sd, (uint64_t)(uint32_t)insn->imm, false); }
        }
        return true;
    }

    // NEG
    if (op == BPF_NEG) { load_dst(); neg_reg(X0, X0, is_64); store_dst(); return true; }

    // MOV sign-extend (off != 0)
    if (op == BPF_MOV) {
        if (is_x) load_bpf(insn->src_reg, X0); else mov_imm(X0, (uint64_t)(int64_t)insn->imm, true);
        if (is_64) {
            switch (insn->off) {
            case 8: sxtb(X0, X0, true); break;
            case 16: sxth(X0, X0, true); break;
            case 32: sxtw(X0, X0); break;
            default: return false;
            }
        } else {
            switch (insn->off) {
            case 8: sxtb(X0, X0, false); break;
            case 16: sxth(X0, X0, false); break;
            default: return false;
            }
        }
        store_dst(); return true;
    }

    // END (byte swap / zero-extend)
    if (op == BPF_END) {
        if (is_64) {
            load_dst();
            switch (insn->imm) {
            case 16: rev16(X0, X0, true); and_imm(X0, X0, 0xFFFF, true); break;
            case 32: rev32(X0, X0); break;
            case 64: rev64(X0, X0); break;
            default: return false;
            }
        } else {
            if (!is_x && insn->imm == 64) return true; // zero-extend to 64 = nop for W ops
            if (is_x) {
                load_dst();
                switch (insn->imm) {
                case 16: rev16(X0, X0, false); and_imm(X0, X0, 0xFFFF, true); break;
                case 32: rev32(X0, X0); break;
                case 64: return false;
                default: return false;
                }
            } else {
                load_dst();
                switch (insn->imm) {
                case 16: and_imm(X0, X0, 0xFFFF, true); break;
                case 32: mov_reg(X0, X0, false); break; // mov W zero-extends
                default: return false;
                }
            }
        }
        store_dst(); return true;
    }

    // Peephole: skip no-op
    if (!is_x) {
        if (insn->imm == 0 && (op == BPF_ADD || op == BPF_SUB || op == BPF_OR ||
            op == BPF_XOR || op == BPF_LSH || op == BPF_RSH || op == BPF_ARSH)) return true;
        if (insn->imm == 1 && (op == BPF_MUL || op == BPF_DIV)) return true;
    }

    // Arithmetic / logic / shift
    uint8_t mask = is_64 ? 0x3F : 0x1F;
    load_dst();
    if (is_x) load_src();

    switch (op) {
    case BPF_ADD: is_x ? add_reg(X0, X0, X1, is_64) : add_imm(X0, X0, insn->imm, is_64); break;
    case BPF_SUB: is_x ? sub_reg(X0, X0, X1, is_64) : sub_imm(X0, X0, insn->imm, is_64); break;
    case BPF_OR:  is_x ? orr_reg(X0, X0, X1, is_64) : orr_imm(X0, X0, (uint64_t)(uint32_t)insn->imm, is_64); break;
    case BPF_AND: is_x ? and_reg(X0, X0, X1, is_64) : and_imm(X0, X0, (uint64_t)(uint32_t)insn->imm, is_64); break;
    case BPF_XOR: is_x ? eor_reg(X0, X0, X1, is_64) : eor_imm(X0, X0, (uint64_t)(uint32_t)insn->imm, is_64); break;
    case BPF_LSH: is_x ? lsl_reg(X0, X0, X1, is_64) : lsl_imm(X0, X0, (uint8_t)(insn->imm & mask), is_64); break;
    case BPF_RSH: is_x ? lsr_reg(X0, X0, X1, is_64) : lsr_imm(X0, X0, (uint8_t)(insn->imm & mask), is_64); break;
    case BPF_ARSH: is_x ? asr_reg(X0, X0, X1, is_64) : asr_imm(X0, X0, (uint8_t)(insn->imm & mask), is_64); break;
    case BPF_MUL:
        if (is_x) {
            mul_reg(X0, X0, X1, is_64);
        } else {
            if (is_64) mov_imm(X1, (uint64_t)(int64_t)insn->imm, true);
            else mov_imm(X1, (uint64_t)(uint32_t)insn->imm, false);
            mul_reg(X0, X0, X1, is_64);
        }
        break;
    case BPF_DIV: {
        if (!is_x) {
            if (insn->imm == 0) {
                mov_imm(X0, 0, is_64);
                store_dst();
                return true;
            }
            mov_imm(X1, (uint64_t)(int64_t)insn->imm, is_64);
        }
        if (insn->off == 0) udiv_reg(X0, X0, X1, is_64);
        else                sdiv_reg(X0, X0, X1, is_64);
        store_dst();
        return true;
    }
    case BPF_MOD: {
        if (!is_x) {
            if (insn->imm == 0) {
                // mod by 0 = dst 不变
                return true;
            }
            mov_imm(X1, (uint64_t)(int64_t)insn->imm, is_64);
        }
        if (insn->off == 0) udiv_reg(X2, X0, X1, is_64);
        else                sdiv_reg(X2, X0, X1, is_64);
        msub_reg(X0, X2, X1, X0, is_64);
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

bool AArch64Emitter::emit_ld(const bpf_insn* insn) {
    uint8_t mode = insn->code & 0xe0, sz = insn->code & 0x18;
    if (mode != BPF_IMM || sz != BPF_DW || insn->dst_reg >= 10) return false;
    uint64_t imm64 = (uint64_t)(uint32_t)(insn + 1)->imm << 32 | (uint32_t)insn->imm;
    mov_imm(BPF_REG_MAP[insn->dst_reg], imm64, true);
    return true;
}

// ---------------------------------------------------------------------------
// LDX / ST / STX
// ---------------------------------------------------------------------------

bool AArch64Emitter::emit_ldx(const bpf_insn* insn, std::vector<AbortPatchInfo>& ap, int bi) {
    uint8_t mode = insn->code & 0xe0, sf = insn->code & 0x18;
    if (mode != BPF_MEM && mode != BPF_MEMSX) return false;
    if (mode == BPF_MEMSX && sf == BPF_DW) return false;
    if (insn->dst_reg >= 10) return false;
    int as; switch (sf) { case BPF_DW: as=8; break; case BPF_W: as=4; break;
                           case BPF_H: as=2; break; case BPF_B: as=1; break; default: return false; }
    auto ctx = begin_mem_access(BPF_REG_MAP[insn->src_reg], insn->off, as, false);
    if (mode == BPF_MEM) {
        switch (sf) {
        case BPF_DW: ldr_imm(X0, X0, 0, true); break;
        case BPF_W:  ldr_imm(X0, X0, 0, false); break;
        case BPF_H:  ldrh(X0, X0, 0); break;
        case BPF_B:  ldrb(X0, X0, 0); break;
        }
    } else {
        switch (sf) {
        case BPF_W:  ldrsw(X0, X0, 0); break;
        case BPF_H:  ldrsh(X0, X0, 0, true); break;
        case BPF_B:  ldrsb(X0, X0, 0, true); break;
        default: return false;
        }
    }
    mov_reg(BPF_REG_MAP[insn->dst_reg], X0, true);
    finish_mem_access(ctx, ap, bi);
    return true;
}

bool AArch64Emitter::emit_st(const bpf_insn* insn, std::vector<AbortPatchInfo>& ap, int bi) {
    uint8_t mode = insn->code & 0xe0, sf = insn->code & 0x18;
    if (mode != BPF_MEM) return false;
    int as; switch (sf) { case BPF_DW: as=8; break; case BPF_W: as=4; break;
                           case BPF_H: as=2; break; case BPF_B: as=1; break; default: return false; }
    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, as, true);
    mov_imm(X1, (uint64_t)(int64_t)insn->imm, true);
    switch (sf) {
    case BPF_DW: str_imm(X1, X0, 0, true); break;
    case BPF_W:  str_imm(X1, X0, 0, false); break;
    case BPF_H:  strh(X1, X0, 0); break;
    case BPF_B:  strb(X1, X0, 0); break;
    }
    finish_mem_access(ctx, ap, bi);
    return true;
}

bool AArch64Emitter::emit_stx(const bpf_insn* insn, std::vector<AbortPatchInfo>& ap, int bi) {
    uint8_t mode = insn->code & 0xe0, sf = insn->code & 0x18;
    if (mode == BPF_ATOMIC) return emit_stx_atomic(insn, ap, bi);
    if (mode != BPF_MEM) return false;
    int as; switch (sf) { case BPF_DW: as=8; break; case BPF_W: as=4; break;
                           case BPF_H: as=2; break; case BPF_B: as=1; break; default: return false; }
    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, as, true);
    load_bpf(insn->src_reg, X1);
    switch (sf) {
    case BPF_DW: str_imm(X1, X0, 0, true); break;
    case BPF_W:  str_imm(X1, X0, 0, false); break;
    case BPF_H:  strh(X1, X0, 0); break;
    case BPF_B:  strb(X1, X0, 0); break;
    }
    finish_mem_access(ctx, ap, bi);
    return true;
}

// ---------------------------------------------------------------------------
// STX atomic: LDAXR/STLXR (LL/SC) read-modify-write
// ---------------------------------------------------------------------------

bool AArch64Emitter::emit_stx_atomic(const bpf_insn* insn,
                                       std::vector<AbortPatchInfo>& ap, int bi) {
    uint8_t sf = insn->code & 0x18;
    if (sf != BPF_DW && sf != BPF_W) return false;
    bool is_dw = (sf == BPF_DW);
    int access_size = is_dw ? 8 : 4;

    auto ctx = begin_mem_access(BPF_REG_MAP[insn->dst_reg], insn->off, access_size, true);

    // X0 = host pointer; save to X2
    mov_reg(X2, X0, true);
    // Load source value into X1
    load_bpf(insn->src_reg, X1);

    // LDAXR encoding: 32-bit = 0x885FFC00, 64-bit = 0xC85FFC00
    // STLXR encoding: 32-bit = 0x8800FC00, 64-bit = 0xC800FC00
    // Rs (status) at bits[20:16], Rn at bits[9:5], Rt at bits[4:0]
    const uint32_t ldaxr_base = is_dw ? 0xC85FFC00u : 0x885FFC00u;
    const uint32_t stlxr_base = is_dw ? 0xC800FC00u : 0x8800FC00u;

    int32_t atom_op = insn->imm;
    bool ok = true;

    // FETCH variants: ADD/OR/AND/XOR with BPF_FETCH
    if ((atom_op & BPF_FETCH) && atom_op != BPF_XCHG && atom_op != BPF_CMPXCHG) {
        uint8_t base_op = atom_op & ~BPF_FETCH;
        if (base_op != BPF_ADD && base_op != BPF_OR &&
            base_op != BPF_AND && base_op != BPF_XOR) {
            ok = false;
        } else {
            size_t loop_start = size();
            // LDAXR X0, [X2] — load current value
            emit_insn(ldaxr_base | ((uint32_t)X2 << 5) | rd(X0));
            // X3 = X0 <op> X1
            switch (base_op) {
            case BPF_ADD: add_reg(X3, X0, X1, is_dw); break;
            case BPF_OR:  orr_reg(X3, X0, X1, is_dw); break;
            case BPF_AND: and_reg(X3, X0, X1, is_dw); break;
            case BPF_XOR: eor_reg(X3, X0, X1, is_dw); break;
            }
            // STLXR W15, X3, [X2]
            emit_insn(stlxr_base | ((uint32_t)X15 << 16) | ((uint32_t)X2 << 5) | rd(X3));
            cbnz(X15, false);
            patch_branch_cond(size() - 4, loop_start);
            // FETCH: store old value (X0) to src_reg
            store_bpf(insn->src_reg, X0, true);
        }
    } else switch (atom_op) {
    case BPF_ADD:
    case BPF_OR:
    case BPF_AND:
    case BPF_XOR: {
        size_t loop_start = size();
        // LDAXR X0, [X2] — load current value
        emit_insn(ldaxr_base | ((uint32_t)X2 << 5) | rd(X0));
        // X0 = X0 <op> X1 (compute new value in-place)
        switch (atom_op) {
        case BPF_ADD: add_reg(X0, X0, X1, is_dw); break;
        case BPF_OR:  orr_reg(X0, X0, X1, is_dw); break;
        case BPF_AND: and_reg(X0, X0, X1, is_dw); break;
        case BPF_XOR: eor_reg(X0, X0, X1, is_dw); break;
        }
        // STLXR W15, X0, [X2]
        emit_insn(stlxr_base | ((uint32_t)X15 << 16) | ((uint32_t)X2 << 5) | rd(X0));
        cbnz(X15, false);
        patch_branch_cond(size() - 4, loop_start);
        break;
    }

    case BPF_XCHG: {
        size_t loop_start = size();
        // LDAXR X3, [X2] — load old value
        emit_insn(ldaxr_base | ((uint32_t)X2 << 5) | rd(X3));
        // STLXR W15, X1, [X2] — store source value
        emit_insn(stlxr_base | ((uint32_t)X15 << 16) | ((uint32_t)X2 << 5) | rd(X1));
        cbnz(X15, false);
        patch_branch_cond(size() - 4, loop_start);
        // Old value → src_reg
        store_bpf(insn->src_reg, X3, true);
        break;
    }

    case BPF_CMPXCHG: {
        // X3 = expected value (BPF r0)
        load_bpf(0, X3);
        size_t loop_start = size();
        // LDAXR X0, [X2] — load current value
        emit_insn(ldaxr_base | ((uint32_t)X2 << 5) | rd(X0));
        // CMP X0, X3 — compare current with expected
        cmp_reg(X0, X3, is_dw);
        // B.NE skip — not equal, skip store
        b_cond(ARMCond::NE);
        size_t ne_jcc = size() - 4;
        // STLXR W15, X1, [X2] — store source
        emit_insn(stlxr_base | ((uint32_t)X15 << 16) | ((uint32_t)X2 << 5) | rd(X1));
        cbnz(X15, false);
        patch_branch_cond(size() - 4, loop_start);
        // skip:
        patch_branch_cond(ne_jcc, size());
        // Current value → BPF r0
        store_bpf(0, X0, true);
        break;
    }

    default:
        ok = false;
        break;
    }

    finish_mem_access(ctx, ap, bi);
    return ok;
}


// ---------------------------------------------------------------------------
// Conditional jumps
// ---------------------------------------------------------------------------

bool AArch64Emitter::emit_jmp(const bpf_insn* insn, int cur, bool is_64,
                                std::vector<JumpPlaceholder>& phs) {
    uint8_t op = insn->code & 0xf0;
    bool is_x = (insn->code & 0x08) == BPF_X;
    if (is_64 && (op == BPF_JA || op == BPF_CALL || op == BPF_EXIT)) return false;
    if (!is_64 && op == BPF_JA) return false;

    uint8_t cc = 0; bool is_test = false;
    switch (op) {
    case BPF_JEQ:  cc = ARMCond::EQ; break;
    case BPF_JNE:  cc = ARMCond::NE; break;
    case BPF_JGT:  cc = ARMCond::HI; break;
    case BPF_JGE:  cc = ARMCond::CS; break; // unsigned >= = carry set
    case BPF_JLT:  cc = ARMCond::CC; break;
    case BPF_JLE:  cc = ARMCond::LS; break;
    case BPF_JSGT: cc = ARMCond::GT; break;
    case BPF_JSGE: cc = ARMCond::GE; break;
    case BPF_JSLT: cc = ARMCond::LT; break;
    case BPF_JSLE: cc = ARMCond::LE; break;
    case BPF_JSET: cc = ARMCond::NE; is_test = true; break;
    default: return false;
    }

    load_bpf(insn->dst_reg, X0);
    if (is_test) {
        if (is_x) { load_bpf(insn->src_reg, X1); tst_reg(X0, X1, is_64); }
        else { mov_imm(X1, (uint64_t)(uint32_t)insn->imm, is_64); tst_reg(X0, X1, is_64); }
    } else {
        if (is_x) { load_bpf(insn->src_reg, X1); cmp_reg(X0, X1, is_64); }
        else cmp_imm(X0, insn->imm, is_64);
    }
    size_t off = size();
    b_cond(cc);
    phs.push_back({off, cur + 1 + insn->off, PlaceholderKind::Conditional});
    return true;
}

void AArch64Emitter::emit_ja(const bpf_insn* insn, int cur, std::vector<JumpPlaceholder>& phs) {
    size_t off = size(); b_uncond();
    phs.push_back({off, cur + 1 + insn->off, PlaceholderKind::Unconditional});
}
void AArch64Emitter::emit_ja32(const bpf_insn* insn, int cur, std::vector<JumpPlaceholder>& phs) {
    size_t off = size(); b_uncond();
    phs.push_back({off, cur + 1 + insn->imm, PlaceholderKind::Unconditional});
}

// ---------------------------------------------------------------------------
// CALL / EXIT
// ---------------------------------------------------------------------------

void AArch64Emitter::emit_call_syscall(const bpf_insn* insn, int cur, const bpf_insn* entry_pc) {
    flush_to_vm();
    // Save pc
    mov_imm(X0, (uint64_t)(uintptr_t)(entry_pc + cur), true);
    str_imm(X0, X28, (int32_t)off_pc_, true);
    // Call helper_do_syscall(vm*, call_id)
    mov_reg(X0, X28, true);
    mov_imm(X1, (uint64_t)(uint32_t)insn->imm, true);
    call_helper(helpers_.do_syscall);
    // Check return (al != 0 means ok)
    cbz(X0, false);
    patch_branch_cond(size() - 4, vm_exit_offset);
    reload_from_vm();
}

void AArch64Emitter::emit_call_bpf(const bpf_insn* insn, int cur, uint64_t ret_gpa, const bpf_insn* entry_pc) {
    flush_to_vm();
    mov_reg(X0, X28, true);
    mov_imm(X1, ret_gpa, true);
    call_helper(helpers_.push_frame);
    cbz(X0, false);
    patch_branch_cond(size() - 4, vm_exit_offset);
    // Set pc to callee
    mov_imm(X0, (uint64_t)(uintptr_t)(entry_pc + cur + 1 + insn->imm), true);
    str_imm(X0, X28, (int32_t)off_pc_, true);
    // Jump to vm_exit
    size_t off = size(); b_uncond();
    patch_branch_uncond(off, vm_exit_offset);
}

void AArch64Emitter::emit_call_indirect(const bpf_insn* insn, uint64_t ret_gpa) {
    flush_to_vm();
    mov_reg(X0, X28, true);                                       // X0 = vm*
    mov_imm(X1, ret_gpa, true);                                   // X1 = ret_gpa
    ldr_imm(X2, X28, (int32_t)(off_reg_ + insn->dst_reg * 8), true); // X2 = target
    call_helper(helpers_.call_indirect);
    size_t off = size(); b_uncond();
    patch_branch_uncond(off, vm_exit_offset);
}

void AArch64Emitter::emit_exit() {
    flush_to_vm();
    mov_reg(X0, X28, true);
    call_helper(helpers_.pop_frame);
    // Test if we got a return address
    cbz(X0, true); // if null → stack bottom
    size_t has_ret_jcc = size() - 4;
    // Has return address: save it, set up args for return_to_caller
    mov_reg(X1, X0, true);       // X1 = return address
    mov_reg(X0, X28, true);      // X0 = vm*
    call_helper(helpers_.return_to_caller);
    size_t exit_jmp = size(); b_uncond();
    patch_branch_uncond(exit_jmp, vm_exit_offset);
    // Stack bottom: set VM_EXITED
    patch_branch_cond(has_ret_jcc, size());
    mov_imm(X0, 1, true);
    add_imm(X1, X28, (int64_t)off_flags_, true);
    size_t atomic_loop = size();
    emit_insn(0x885FFC00u | ((uint32_t)X1 << 5) | rd(X2));   // LDAXR W2, [X1] (32-bit, acquire)
    orr_reg(X2, X2, X0, false);                                // ORR W2, W2, W0
    emit_insn(0x8800FC00u | ((uint32_t)X15 << 16) | ((uint32_t)X1 << 5) | rd(X2)); // STLXR W15, W2, [X1]
    cbnz(X15, false);
    patch_branch_cond(size() - 4, atomic_loop);
    size_t bottom_jmp = size(); b_uncond();
    patch_branch_uncond(bottom_jmp, vm_exit_offset);
}

// ---------------------------------------------------------------------------
// Prologue
// Entry: X0 = vm*
// ---------------------------------------------------------------------------

size_t AArch64Emitter::emit_prologue() {
    // Save callee-saved: X19-X23, X28, X29, X30 (8 regs = 64 bytes)
    add_imm(SP, SP, -64, true);
    stp(X19, X20, SP, 0, true);
    stp(X21, X22, SP, 16, true);
    stp(X23, X28, SP, 32, true);
    stp(FP, LR, SP, 48, true);

    // X28 = vm*
    mov_reg(X28, X0, true);

    // Load all 11 BPF registers from vm->reg[]
    for (int i = 0; i < 11; i++)
        ldr_imm(BPF_REG_MAP[i], X28, (int32_t)(off_reg_ + i * 8), true);

    // B .entry (placeholder)
    size_t entry_jmp = size(); b_uncond();

    // .vm_exit: restore callee-saved, return
    vm_exit_offset = size();
    ldp(X19, X20, SP, 0, true);
    ldp(X21, X22, SP, 16, true);
    ldp(X23, X28, SP, 32, true);
    ldp(FP, LR, SP, 48, true);
    add_imm(SP, SP, 64, true);
    ret();

    // .flush_and_exit: write all BPF regs to vm->reg[], then B .vm_exit
    size_t flush_and_exit_offset = size();
    for (int i = 0; i < 10; i++)
        str_imm(BPF_REG_MAP[i], X28, (int32_t)(off_reg_ + i * 8), true);
    size_t jmp_off = size(); b_uncond();
    patch_branch_uncond(jmp_off, vm_exit_offset);

    // .entry: safepoint
    patch_branch_uncond(entry_jmp, size());
    flush_to_vm();
    mov_reg(X0, X28, true);
    call_helper(helpers_.safepoint);
    // helper returns 0=ok, non-zero=exit. CBNZ W0 → vm_exit
    cbnz(X0, false);
    patch_branch_cond(size() - 4, vm_exit_offset);
    reload_caller_saved();

    return flush_and_exit_offset;
}

// ---------------------------------------------------------------------------
// Safepoint (at loop back-edge targets)
// ---------------------------------------------------------------------------

void AArch64Emitter::emit_safepoint(uint32_t loop_body_size) {
    if (insn_count_enabled_) {
        // --- 指令计数递增 ---
        // X0 = insn_count, X1 = loop_body_size
        ldr_imm(X0, X28, (int32_t)off_insn_count_, true);
        add_imm(X0, X0, (int64_t)loop_body_size, true);
        str_imm(X0, X28, (int32_t)off_insn_count_, true);

        if (budget_enabled_) {
            // --- 预算检查 ---
            // X1 = insn_limit
            ldr_imm(X1, X28, (int32_t)off_insn_limit_, true);
            cmp_reg(X0, X1, true);  // compare insn_count vs insn_limit
            size_t budget_ok_b = size();
            b_cond(ARMCond::CC);  // B.CC .check_flags (unsigned below, count < limit)

            // .budget_exceeded: atomically set VM_BUDGET_EXCEEDED flag
            // Use LDAXR/STLXR loop to avoid clobbering concurrent flag writes
            // (e.g. VM_KILLED from another thread). Matches x86's `lock or`.
            // LDAXR/STLXR don't support offset addressing, so compute &flags in X2 first.
            add_imm(X2, X28, (int64_t)off_flags_, true);  // X2 = &vm->flags
            const uint32_t ldaxr_w = 0x885FFC00u;  // LDAXR Wt, [Xn]
            const uint32_t stlxr_w = 0x8800FC00u;  // STLXR Ws, Wt, [Xn]
            size_t retry = size();
            emit_insn(ldaxr_w | ((uint32_t)X2 << 5) | rd(X0));    // LDAXR W0, [X2]
            // 用 X15 做 ORR 的 scratch，避免 orr_imm 内部 clobber X2（X2 存着 flags 地址）
            mov_imm(X15, vm::VM_BUDGET_EXCEEDED, false);
            orr_reg(X0, X0, X15, false);                           // W0 |= VM_BUDGET_EXCEEDED
            // X1 is reused as the exclusive store status register (Ws)
            emit_insn(stlxr_w | ((uint32_t)X1 << 16) | ((uint32_t)X2 << 5) | rd(X0));  // STLXR W1, W0, [X2]
            cbnz(X1, false);
            patch_branch_cond(size() - 4, retry);  // retry if exclusive store failed
            size_t budget_exit = size();
            b_uncond();
            patch_branch_uncond(budget_exit, vm_exit_offset);

            // .check_flags:
            patch_branch_cond(budget_ok_b, size());
        }
    }

    // flags 非零即进入慢路径
    ldr_imm(X0, X28, (int32_t)off_flags_, false);  // W0 = flags (32-bit load)
    size_t slow_patch = size();
    cbnz(X0, false);  // CBNZ W0, .slow_safepoint

    // Fast path: all clear
    size_t fast_jmp = size(); b_uncond();

    // .slow_safepoint
    size_t slow = size();
    patch_branch_cond(slow_patch, slow);

    flush_to_vm();
    mov_reg(X0, X28, true);
    call_helper(helpers_.safepoint);
    // helper returns 0=ok, non-zero=exit
    cbnz(X0, false);
    patch_branch_cond(size() - 4, vm_exit_offset);
    reload_caller_saved();

    // .done
    patch_branch_uncond(fast_jmp, size());
}

#endif // __aarch64__
