//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include "../include/bpf_fp.h"
#include <iostream>

#include "jit/jit.h"
#include "../include/auxv.h"
#include <cstring>
#include <cmath>
#include <algorithm>

#if defined(__x86_64__)
#include "jit/jit_compiler.h"
#include "jit/x86_emitter.h"
using JitCompilerImpl = JitCompiler<X86Emitter>;
#elif defined(__aarch64__)
#include "jit/jit_compiler.h"
#include "jit/aarch64_emitter.h"
using JitCompilerImpl = JitCompiler<AArch64Emitter>;
#else
class StubJitCompiler : public JitCompilerBase {
public:
    JitEntry* compile(vm*, uint64_t) override { return nullptr; }
};
using JitCompilerImpl = StubJitCompiler;
#endif

#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <mutex>
#include <time.h>


std::mutex log_mutex;



void dump(uint64_t addr, const bpf_insn* insn) {
    static const char* aluop[] = {
        "add", "sub", "mul", "div", "or", "and", "lsh",
        "rsh", "neg", "mod", "xor", "mov", "arsh", "end"
    };
    static const char* jmpop[] = {
        "ja", "jeq", "jgt", "jge", "jset", "jne", "jsgt",
        "jsge", "call", "exit", "jlt", "jle", "jslt", "jsle"
    };
    static const char* lsize[] = {
        "w", "h", "b", "dw"
    };
    printf("%" PRIx64 ": 0x%02x %d %d %d 0x%x: ", addr, insn->code, insn->dst_reg, insn->src_reg, insn->off, insn->imm);
    switch(insn->code & 0x07) {
    case BPF_ALU: case BPF_ALU64: {
        printf("%s ", aluop[(insn->code & 0xf0) >> 4]);
        printf("r%d ", insn->dst_reg);
        if ((insn->code & 0xf0) == BPF_END) { // Specific formatting for BPF_END
            if ((insn->code & 0x08) == BPF_X) { // BPF_TO_BE (corresponds to BPF_X value 0x08)
                printf("be, %d\n", insn->imm); // imm is width
            } else { // BPF_TO_LE (corresponds to BPF_K value 0x00)
                printf("le, %d\n", insn->imm); // imm is width
            }
        } else { // Formatting for other ALU operations
            if((insn->code & 0x08) == BPF_X) { // Source is register
                printf("r%d\n", insn->src_reg);
            } else { // Source is immediate
                printf("%d\n", insn->imm);
            }
        }
        break;
    }
    case BPF_JMP: case BPF_JMP32: {
        printf("%s ", jmpop[(insn->code & 0xf0) >> 4]);
        if((insn->code & 0xf0) == BPF_EXIT){
            printf("\n");
        }else if((insn->code & 0xf0) == BPF_JA){
            if((insn->code & 0x07) == BPF_JMP32){
                printf("%d\n", insn->imm);
            }else{
                printf("%d\n", insn->off);
            }
        }else if((insn->code & 0xf0) == BPF_CALL){
            if(insn->code & 0x08)
                printf("r%d\n", insn->dst_reg);
            else if(insn->src_reg == 0) {
                printf("sys 0x%X\n", insn->imm);
            }else if(insn->src_reg == 1) {
                printf("%d\n", insn->imm);
            }else if(insn->src_reg == 2) {
                printf("fp 0x%X\n", insn->imm);
            }else {
                printf("!unknown!\n");
            }
        }else if((insn->code & 0x08) == BPF_X) {
            printf("r%d r%d %d\n", insn->dst_reg, insn->src_reg, insn->off);
        } else {
            printf("r%d %d %d\n", insn->dst_reg, insn->imm, insn->off);
        }
        break;
    }
    case BPF_LD: {
        printf("ld%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_IMM) {
            fprintf(stderr, "Invalid mode for ld\n");
            return;
        }
        printf("r%d 0x%lx\n", insn->dst_reg, (uint64_t)(insn+1)->imm << 32 | (uint32_t)insn->imm);
        break;
    }
    case BPF_LDX: {
        printf("ldx%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM && (insn->code & 0xe0) != BPF_MEMSX) {
            fprintf(stderr, "Invalid mode for ldx\n");
            return;
        }
        printf("r%d ", insn->dst_reg);
        if(insn->off == 0) {
            printf("[r%d]\n", insn->src_reg);
        } else if(insn->off > 0){
            printf("[r%d+%d]\n", insn->src_reg, insn->off);
        } else {
            printf("[r%d%d]\n", insn->src_reg, insn->off);
        }
        break;
    }
    case BPF_ST: {
        printf("st%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM) {
            fprintf(stderr, "Invalid mode for st\n");
            return;
        }
        if(insn->off == 0) {
            printf("[r%d] ", insn->dst_reg);
        }else if(insn->off > 0) {
            printf("[r%d+%d] ", insn->dst_reg, insn->off);
        } else {
            printf("[r%d%d] ", insn->dst_reg, insn->off);
        }
        printf("%d\n", insn->imm);
        break;
    }
    case BPF_STX: {
        if((insn->code & 0xe0) == BPF_ATOMIC) {
            static const char* atomicop[] = {
                "add", "or", "and", "xor",
            };
            const char* size = (insn->code & 0x18) == BPF_DW ? "64" : "32";
            int32_t op = insn->imm;
            if(insn->off == 0) {
                printf("lock%s [r%d] ", size, insn->dst_reg);
            } else if(insn->off > 0) {
                printf("lock%s [r%d+%d] ", size, insn->dst_reg, insn->off);
            } else {
                printf("lock%s [r%d%d] ", size, insn->dst_reg, insn->off);
            }
            int base_op = op & ~BPF_FETCH;
            if(base_op == (BPF_XCHG & ~BPF_FETCH)) {
                printf("xchg r%d\n", insn->src_reg);
            } else if(base_op == (BPF_CMPXCHG & ~BPF_FETCH)) {
                printf("cmpxchg r%d\n", insn->src_reg);
            } else if(base_op == BPF_ADD || base_op == BPF_OR ||
                      base_op == BPF_AND || base_op == BPF_XOR) {
                int idx = base_op == BPF_ADD ? 0 : base_op == BPF_OR ? 1 :
                          base_op == BPF_AND ? 2 : 3;
                if(op & BPF_FETCH) {
                    printf("fetch_%s r%d\n", atomicop[idx], insn->src_reg);
                } else {
                    printf("%s r%d\n", atomicop[idx], insn->src_reg);
                }
            } else {
                printf("unknown(0x%x) r%d\n", op, insn->src_reg);
            }
            break;
        }
        printf("stx%s ", lsize[(insn->code & 0x18) >> 3]);
        if((insn->code & 0xe0) != BPF_MEM) {
            fprintf(stderr, "Invalid mode for stx\n");
            return;
        }
        if(insn->off == 0) {
            printf("[r%d] ", insn->dst_reg);
        }else if(insn->off > 0) {
            printf("[r%d+%d] ", insn->dst_reg, insn->off);
        } else {
            printf("[r%d%d] ", insn->dst_reg, insn->off);
        }
        printf("r%d\n", insn->src_reg);
        break;
    }
    default:
        break;
    }
}

vm::vm(Token) {
    pthread_mutex_init(&wait_mutex, nullptr);
    pthread_cond_init(&wait_cv, nullptr);
    memset(reg, 0, sizeof(reg));
}

vm::~vm() {
    pthread_cond_destroy(&wait_cv);
    pthread_mutex_destroy(&wait_mutex);
}

std::shared_ptr<vm> vm::create() {
    return std::make_shared<vm>(Token{});
}

ElfLoadInfo vm::load_elf(int fd, const char* elf_file_path, const std::map<std::string, std::string>& envp) {
    auto info = ::load_elf(fd, elf_file_path, [this](memmap&& m) { addmem(std::move(m)); }, envp);
    // fd 所有权交接见 elf_loader.h（借用）与 vmImage::fd（析构关）：成功构造 image 存入，
    // 失败立即关（exec 流程的 fresh 不跑 run()，不关就泄漏）。
    if(info.entry != 0) {
        set_image(std::make_shared<vmImage>(info.entry, info.app_load_base, elf_file_path, fd));
    } else {
        close(fd);
    }
    return info;
}

/*
 * Stack Frame Layout（frame_base[0] 编码见 insn.h）：
 *
 * old_r10 / RA 固定在 r10+8 / r10+16（与帧类型无关），这样 DWARF CFI 一套规则即可
 * 通吃普通帧和信号帧（elf_linker.cpp 合成 .debug_frame）。
 *
 * 公共头 [0..6]（普通/信号帧一致）：
 * +------------------+-------------+
 * | is_signal+len    | frame_base[0]   r10+0
 * | old_r10 (SP)     | frame_base[1]   r10+8
 * | return_address   | frame_base[2]   r10+16
 * | r6/r7/r8/r9      | frame_base[3..6] r10+24..48
 * +------------------+-------------+
 * 普通帧 64B：以上 [0..6] + [7] unused。
 * 信号帧 128B：[0..6] + frame_base[7..12]=r0..r5（caller-saved，信号可打断任意时刻），
 *              [13..15] unused。
 */
bool vm::push_frame(uint64_t return_addr, bool is_signal) {
    uint32_t frame_size = is_signal ? SIGNAL_FRAME_SIZE : NORMAL_FRAME_SIZE;
    // 调用者（被中断函数）栈帧的总长度 = stack_limit + alloca_len，读"当前 r10
    //   处那个帧"frame_base[0] 的低 32 位。调用者的局部变量区是
    //   [r10 - stack_limit, r10]，alloca 区在其下 [r10 - total_len, r10 - stack_limit]。
    uint64_t* cur_frame = (uint64_t*)mmu(r(10), sizeof(uint64_t));
    uint64_t caller_total_len = cur_frame ? frame_total_len(cur_frame[0]) : 0;
    if(r(10) - caller_total_len - frame_size < STACK_BASE) {
        log_mem_violation("stack overflow", r(10));
        return false;
    }
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] PUSH sp=%lx ret=%lx sig=%d size=%d caller_len=%lu\n",
            options.sys->id(), r(10), return_addr, is_signal, frame_size, caller_total_len);
    }
    uint64_t sp = r(10) - caller_total_len;
    uint64_t frame_base_addr = sp - frame_size;
    // 检查整段新帧 [frame_base_addr, sp)
    uint64_t* frame_base = (uint64_t*)mmu_w(frame_base_addr, sp - frame_base_addr);
    if(!frame_base) {
        log_mem_violation("stack access", frame_base_addr);
        return false;
    }

    // is_signal 标志位(bit32) + total_len(=stack_limit，低 32 位)；新函数局部变量区尚未 alloca。
    frame_base[0] = frame_flags_make(is_signal, options.stack_limit);
    // 公共锚点：old_r10 / RA 固定在 [1] / [2]（与帧类型无关）。
    frame_base[1] = r(10);
    frame_base[2] = return_addr;
    frame_base[3] = r(6);
    frame_base[4] = r(7);
    frame_base[5] = r(8);
    frame_base[6] = r(9);
    if (is_signal) {
        signal_depth++;
        // 信号帧额外保存 caller-saved r0..r5（信号可打断任意时刻）。
        frame_base[7]  = r(0);
        frame_base[8]  = r(1);
        frame_base[9]  = r(2);
        frame_base[10] = r(3);
        frame_base[11] = r(4);
        frame_base[12] = r(5);
    }

    r(10) = frame_base_addr;
    return true;
}

bool vm::deliver_signal() {
    sig_info info;
    if(!options.sys->handle_signals(this, &info)) {
        return false;
    }
    if(info.sig == 0) {
        // 无可投递信号。若有待决 ERESTARTSYS（典型场景：停止后由 SIGCONT 恢复，
        // 或所有 pending 信号被 sigmask 阻塞），默认重启：pc 回到 syscall 指令，
        // step 随后取指即重执行。Linux 内核在 arch_do_signal_or_restart 中对
        // ERESTARTSYS* 的处理同此（无信号投递时一律 restart）。
        if(restart_syscall_pc_ != 0) {
            pc_ = restart_syscall_pc_;
            restart_syscall_pc_ = 0;
        }
        return true;
    }
    if(!mmu(info.handler)) {
        return false;
    }
    // 信号帧的返回地址。无待决重启时用当前 pc（被中断处）；有待决 ERESTARTSYS 时
    // 按 SA_RESTART 决定：置 SA_RESTART -> 返回 syscall 指令（重启）；否则返回 syscall
    // 的下一条指令，并填 r(0) = -EINTR（语义同 Linux：未带 SA_RESTART 的信号打断
    // 可重启 syscall 后向用户态返回 -EINTR）。
    uint64_t ret_addr = pc_;
    if(restart_syscall_pc_ != 0) {
        if(info.sa_flags & SA_RESTART) {
            ret_addr = restart_syscall_pc_;
        } else {
            r(0) = (uint64_t)(int64_t)-EINTR;
            ret_addr = restart_syscall_pc_ + sizeof(bpf_insn);
        }
        restart_syscall_pc_ = 0;
    }
    if(!push_frame(ret_addr, true)) {
        return false;
    }
    r(1) = static_cast<uint64_t>(info.sig);
    pc_ = info.handler;
    return true;
}

uint64_t vm::pop_frame() {
    uint64_t sp = r(10);
    uint64_t* frame_base = (uint64_t*)mmu(sp);
    if(!frame_base) return 0;

    uint64_t old_sp;
    uint64_t ret_addr;
    bool is_signal = frame_is_signal(frame_base[0]);
    // 公共锚点：old_r10 / RA 固定在 [1] / [2]。
    old_sp = frame_base[1];
    ret_addr = frame_base[2];
    r(6) = frame_base[3];
    r(7) = frame_base[4];
    r(8) = frame_base[5];
    r(9) = frame_base[6];
    if (is_signal) {
        signal_depth--;
        // 信号帧额外恢复 caller-saved r0..r5。
        r(0) = frame_base[7];
        r(1) = frame_base[8];
        r(2) = frame_base[9];
        r(3) = frame_base[10];
        r(4) = frame_base[11];
        r(5) = frame_base[12];
    }

    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] POP sp=%lx new_sp=%lx ret=%lx sig=%d\n",
            options.sys->id(), sp, old_sp, ret_addr, is_signal);
    }
    r(10) = old_sp;
    return ret_addr;
}


// alloca(inc) — 当前栈帧 alloca 区的增量调整
// 栈布局（每个函数从其 r10 向下）：
//     [r10 - stack_limit, r10)                              编译器分配的局部变量区
//     [r10 - total_len, r10 - stack_limit)                  本函数已 alloca 的区
//     ...                                                   本函数帧头 / 调用者
//
// 三种用法
//   inc > 0：扩展 inc 字节。新块 = [新下界, 新下界 + inc) = [r10 - new_total,
//            r10 - new_total + inc)，紧贴上一块 alloca 下方，块间不重叠。
//            返回新下界正是新块起始地址（C alloca 语义：buf[0] 在 ret，
//            buf[i] 在 ret+i*sizeof(T)）。
//   inc = 0：只读，返回当前下界
//   inc < 0：收缩 -inc 字节，返回新下界（高于旧下界，往高地址截回）
//
// 注意：栈往低地址生长，所以 inc 的符号是 "alloca_len 增量"，不是 "下界地址增量"
// （符合 C alloca(n) 中 n > 0 即分配的直觉）。
int64_t vm::alloca(int64_t inc) {
    uint64_t stack_limit = options.stack_limit;

    // 当前 r10 处的帧头：读 frame_base[0]，更新其低 32 位的 total_len。
    uint64_t* frame = (uint64_t*)mmu_w(r(10), sizeof(uint64_t));
    if(!frame) return -EFAULT;
    uint64_t flags0 = frame[0];
    uint64_t cur_total = frame_total_len(flags0);

    // 防御：若 frame[0] 损坏 / 旧 ABI 残留（total_len < stack_limit）—— 拒绝。
    if(cur_total < stack_limit) return -EFAULT;
    int64_t cur_alloca = (int64_t)(cur_total - stack_limit);

    // 带符号累加；负到越过 0 视为错误（不能缩进局部变量区）。
    int64_t new_alloca = cur_alloca + inc;
    if(new_alloca < 0) return -EINVAL;
    uint64_t new_total = stack_limit + (uint64_t)new_alloca;

    // 32 位长度编码上限 + 栈区下界不得低于 STACK_BASE。
    if(new_total > FRAME_LEN_MASK || r(10) < STACK_BASE + new_total)
        return -ENOMEM;

    // 扩展时（inc>0）保证新 alloca 区 [r10-new_total, r10) 整段在同一可写映射里
    if(inc > 0 && !mmu_w(r(10) - new_total, new_total))
        return -ENOMEM;

    // 保留 is_signal 等高位，仅替换低 32 位的 total_len。
    frame[0] = (flags0 & ~FRAME_LEN_MASK) | (new_total & FRAME_LEN_MASK);

    // 返回新下界（= inc>0 时新块起始地址；= inc=0 时当前下界作 stacksave token）。
    return (int64_t)(r(10) - new_total);
}


// ---------------------------------------------------------------------------
// 虚拟浮点指令的解释器实现
// r1/r2 是操作数位模式，用宿主硬件浮点算出结果，位模式写回 r0。
// 解释器经 src_reg=2 的 dispatch 直达此处；JIT 无原生 lowering 时（如 x86 的
// uint 转换）经 emit_call_softfp_slow 回退到此处（helper_do_softfp）。
// call 即 imm 字段，本身就是 BPF_FP_* 编号（1..N，无 BASE 偏移），直接 switch。
// ---------------------------------------------------------------------------
bool vm::do_softfp(uint32_t call) {
    const uint32_t op = call;   // FP 编号空间独立，imm 即 BPF_FP_* 值，无需 BPF_CALL_TO_ID

    // 取出两个 i64 操作数（比较/算术用 r1,r2；一元只用 r1）。
    // 题外：glue 函数中所有位转换（double<->i64）已被 clang 优化为寄存器直传，
    // 因此 r1/r2 直接就是操作数的 IEEE754 bit pattern。
    const uint64_t a_bits = r(1);
    const uint64_t b_bits = r(2);

    auto d_in = [](uint64_t u) {
        double d;
        memcpy(&d, &u, sizeof(d));
        return d;
    };
    auto f_in = [](uint64_t u) {
        float f;
        uint32_t b = (uint32_t)u;
        memcpy(&f, &b, sizeof(f));
        return f;
    };
    auto d_out = [](double d) -> uint64_t {
        uint64_t u;
        memcpy(&u, &d, sizeof(u));
        return u;
    };
    auto f_out = [](float f) -> uint32_t {
        uint32_t u;
        memcpy(&u, &f, sizeof(u));
        return u;
    };

    switch (op) {
    // double 二元算术
    case BPF_FP_ADD_D: r(0) = d_out(d_in(a_bits) + d_in(b_bits)); return true;
    case BPF_FP_SUB_D: r(0) = d_out(d_in(a_bits) - d_in(b_bits)); return true;
    case BPF_FP_MUL_D: r(0) = d_out(d_in(a_bits) * d_in(b_bits)); return true;
    case BPF_FP_DIV_D: r(0) = d_out(d_in(a_bits) / d_in(b_bits)); return true;
    // float 二元算术
    case BPF_FP_ADD_F: r(0) = (uint64_t)f_out(f_in(a_bits) + f_in(b_bits)); return true;
    case BPF_FP_SUB_F: r(0) = (uint64_t)f_out(f_in(a_bits) - f_in(b_bits)); return true;
    case BPF_FP_MUL_F: r(0) = (uint64_t)f_out(f_in(a_bits) * f_in(b_bits)); return true;
    case BPF_FP_DIV_F: r(0) = (uint64_t)f_out(f_in(a_bits) / f_in(b_bits)); return true;
    // 一元
    case BPF_FP_NEG_D: r(0) = d_out(-d_in(a_bits)); return true;
    case BPF_FP_NEG_F: r(0) = (uint64_t)f_out(-f_in(a_bits)); return true;
    case BPF_FP_SQRT_D: r(0) = d_out(__builtin_sqrt(d_in(a_bits))); return true;
    case BPF_FP_SQRT_F: r(0) = (uint64_t)f_out(__builtin_sqrtf(f_in(a_bits))); return true;
    // double -> int（截断向 0）
    case BPF_FP_D2SI:  r(0) = (uint64_t)(int64_t)(int32_t)d_in(a_bits); return true;
    case BPF_FP_D2DI:  r(0) = (uint64_t)(int64_t)d_in(a_bits); return true;
    case BPF_FP_D2USI: r(0) = (uint64_t)(uint64_t)(uint32_t)d_in(a_bits); return true;
    case BPF_FP_D2UDI: r(0) = (uint64_t)(uint64_t)d_in(a_bits); return true;
    // float -> int
    case BPF_FP_F2SI:  r(0) = (uint64_t)(int64_t)(int32_t)f_in(a_bits); return true;
    case BPF_FP_F2DI:  r(0) = (uint64_t)(int64_t)f_in(a_bits); return true;
    case BPF_FP_F2USI: r(0) = (uint64_t)(uint64_t)(uint32_t)f_in(a_bits); return true;
    case BPF_FP_F2UDI: r(0) = (uint64_t)(uint64_t)f_in(a_bits); return true;
    // int -> double
    case BPF_FP_SI2D:  r(0) = d_out((double)(int64_t)(int32_t)a_bits); return true;
    case BPF_FP_DI2D:  r(0) = d_out((double)(int64_t)a_bits); return true;
    case BPF_FP_USI2D: r(0) = d_out((double)(uint64_t)(uint32_t)a_bits); return true;
    case BPF_FP_UDI2D: r(0) = d_out((double)(uint64_t)a_bits); return true;
    // int -> float
    case BPF_FP_SI2F:  r(0) = (uint64_t)f_out((float)(int64_t)(int32_t)a_bits); return true;
    case BPF_FP_DI2F:  r(0) = (uint64_t)f_out((float)(int64_t)a_bits); return true;
    case BPF_FP_USI2F: r(0) = (uint64_t)f_out((float)(uint64_t)(uint32_t)a_bits); return true;
    case BPF_FP_UDI2F: r(0) = (uint64_t)f_out((float)(uint64_t)a_bits); return true;
    // 类型转换
    case BPF_FP_EXTEND: r(0) = d_out((double)f_in(a_bits)); return true;
    case BPF_FP_TRUNC:  r(0) = (uint64_t)f_out((float)d_in(a_bits)); return true;
    // 比较：返回 -1/0/1（GCC 软浮点 ABI）。glue 侧的 __eq/__ne/__lt/...
    // 都映射到同一个 CMP helper；对于 == 和 != 的 unordered 处理由调用点
    // 的谓词决定（<0/=0/>0），这里统一返回有序比较的三态结果。
    case BPF_FP_CMP_D: {
        double a = d_in(a_bits), b = d_in(b_bits);
        r(0) = (a < b) ? (uint64_t)-1 : (a > b) ? 1ULL : 0ULL;
        return true;
    }
    case BPF_FP_CMP_F: {
        float a = f_in(a_bits), b = f_in(b_bits);
        r(0) = (a < b) ? (uint64_t)-1 : (a > b) ? 1ULL : 0ULL;
        return true;
    }
    // 无序判定：任一操作数为 NaN 返回 1，否则 0（__unordXX2 语义）。
    // 利用 IEEE754 不等性（NaN != NaN）判定，不依赖 <cmath>。
    case BPF_FP_UNORD_D: {
        double a = d_in(a_bits), b = d_in(b_bits);
        r(0) = (a != a || b != b) ? 1ULL : 0ULL;
        return true;
    }
    case BPF_FP_UNORD_F: {
        float a = f_in(a_bits), b = f_in(b_bits);
        r(0) = (a != a || b != b) ? 1ULL : 0ULL;
        return true;
    }
    // fabs/copysign：musl 实现体是一条位运算，会被 instcombine 折叠回同名 intrinsic，
    case BPF_FP_FABS_D: r(0) = d_out(std::fabs(d_in(a_bits))); return true;
    case BPF_FP_FABS_F: r(0) = (uint64_t)f_out(std::fabs(f_in(a_bits))); return true;
    case BPF_FP_COPYSIGN_D: r(0) = d_out(std::copysign(d_in(a_bits), d_in(b_bits))); return true;
    case BPF_FP_COPYSIGN_F: r(0) = (uint64_t)f_out(std::copysign(f_in(a_bits), f_in(b_bits))); return true;
    // 整数宽乘取高半：r0 = (a*b) >> 64。
    case BPF_FP_UMULH:
        r(0) = (uint64_t)(__uint128_t(a_bits) * b_bits >> 64);
        return true;
    // 128 位整数除法/取模：入参 r1=out_hi(ptr) r2=aLo r3=aHi r4=bLo r5=bHi，
    // 低半返回 r0，高半写入 r1 指向的 8 字节。用宿主 __int128 算；除零返回 0（LLVM
    // 语义 sdiv/udiv X,0 是 poison，宿主 __int128/0 会 SIGFPE 崩溃 host，故显式拦截）。
    // 有符号变体用 __int128（C 的 / 和 % 对有符号截断向零，与 LLVM sdiv/srem 一致）。
    case BPF_FP_UDIV128: case BPF_FP_UREM128:
    case BPF_FP_SDIV128: case BPF_FP_SREM128: {
        uint64_t aLo = r(2), aHi = r(3), bLo = r(4), bHi = r(5);
        uint64_t resLo, resHi;
        if (bLo == 0 && bHi == 0) {     // 除零：返回 0
            resLo = 0; resHi = 0;
        } else if (op == BPF_FP_UDIV128 || op == BPF_FP_UREM128) {
            __uint128_t a = ((__uint128_t)aHi << 64) | aLo;
            __uint128_t b = ((__uint128_t)bHi << 64) | bLo;
            __uint128_t res = (op == BPF_FP_UDIV128) ? a / b : a % b;
            resLo = (uint64_t)res;
            resHi = (uint64_t)(res >> 64);
        } else {
            // 有符号：高半需符号扩展，先转 int64_t 再扩到 __int128。
            // 用 int64_t（stdint.h）而非 __int64_t（宿主内部 typedef，BPF 交叉
            // 编译时未定义，insn.cpp 也编进 bpfvm.bpf）。
            __int128 a = ((__int128)(int64_t)aHi << 64) | (__uint128_t)aLo;
            __int128 b = ((__int128)(int64_t)bHi << 64) | (__uint128_t)bLo;
            __int128 res = (op == BPF_FP_SDIV128) ? a / b : a % b;
            resLo = (uint64_t)res;
            resHi = (uint64_t)((__uint128_t)res >> 64);
        }
        // 高半写入 guest 内存（out_hi = r1），低半回 r0。
        if (uint64_t *out = (uint64_t*)mmu_w(r(1), 8)) {
            *out = resHi;
        } else {
            return false;
        }
        r(0) = resLo;
        return true;
    }
    default:
        r(0) = -ENOSYS;
        return true;
    }
}

bool vm::jmp(const bpf_insn* cur) {
    uint64_t src = (cur->code & 0x08) == BPF_X ? r(cur->src_reg) : cur->imm;
    switch (cur->code & 0xf0) {
    case BPF_JA:
        pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        break;
    case BPF_JEQ:
        if (r(cur->dst_reg) == src) { 
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGT:
        if (r(cur->dst_reg) > src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGE:
        if (r(cur->dst_reg) >= src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSET:
        if (r(cur->dst_reg) & src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JNE:
        if (r(cur->dst_reg) != src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGT:
        if ((int64_t)r(cur->dst_reg) > (int64_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGE:
        if ((int64_t)r(cur->dst_reg) >= (int64_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_CALL:
        if((cur->code & 0x08) == BPF_X) {
            if(!push_frame(pc_ + sizeof(bpf_insn))) {
                return false;
            }
            pc_ = r(cur->dst_reg) - sizeof(bpf_insn);
        }else if(cur->src_reg == 0) {
            return do_syscall(cur->imm);
        }else if(cur->src_reg == 1) {
            if(!push_frame(pc_ + sizeof(bpf_insn))) {
                return false;
            }
            pc_ += (int64_t)cur->imm * sizeof(bpf_insn);
        }else if(cur->src_reg == 2) {
            return do_softfp(cur->imm);
        }
        break;
    case BPF_EXIT:
    {
        uint64_t ret = pop_frame();
        if(ret == 0) {
            //到栈底了
            return false;
        }
        pc_ = ret - sizeof(bpf_insn);  // run() 循环的 pc+=sizeof(bpf_insn) 会落到 ret
        break;
    }
    case BPF_JLT:
        if (r(cur->dst_reg) < src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JLE:
        if (r(cur->dst_reg) <= src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLT:
        if ((int64_t)r(cur->dst_reg) < (int64_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLE:
        if ((int64_t)r(cur->dst_reg) <= (int64_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    }
    return true;
}

bool vm::jmp32(const bpf_insn* cur) {
    uint32_t src = (cur->code & 0x08) == BPF_X ? (uint32_t)r(cur->src_reg) : cur->imm;
    auto dst = (uint32_t)r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_JA:
        pc_ += (int64_t)cur->imm * sizeof(bpf_insn);
        break;
    case BPF_JEQ:
        if (dst == src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGT:
        if (dst > src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JGE:
        if (dst >= src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSET:
        if (dst & src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JNE:
        if (dst != src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGT:
        if ((int32_t)dst > (int32_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSGE:
        if ((int32_t)dst >= (int32_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_CALL:
    case BPF_EXIT:
        return false;
    case BPF_JLT:
        if (dst < src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JLE:
        if (dst <= src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLT:
        if ((int32_t)dst < (int32_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    case BPF_JSLE:
        if ((int32_t)dst <= (int32_t)src) {
            pc_ += (int64_t)cur->off * sizeof(bpf_insn);
        }
        break;
    }
    return true;
}


void vm::log_mem_violation(const char* type, uint64_t addr) {
    std::cerr << "Memory access violation at PC 0x" << std::hex << pc_
              << ": invalid " << type << " at address 0x" << addr << std::dec << std::endl;

    // 寄存器转储
    std::cerr << "Registers:" << std::hex;
    for (int i = 0; i < 11; i++) {
        if (i % 4 == 0) std::cerr << "\n  ";
        std::cerr << "r" << std::dec << i << "=0x" << std::hex << reg[i] << "  " << std::dec;
    }
    std::cerr << std::endl;

    // 调用栈回溯：沿 frame 链向上遍历
    // 正常帧: flags+alloca_len[0] r6..r9[1..4] old_r10[5] ret_addr[6]
    // 信号帧: flags+alloca_len[0] r0..r9[1..10] old_r10[11] ret_addr[12]
    std::cerr << "Call stack:" << std::hex;
    uint64_t cur_sp = r(10);
    uint64_t cur_pc = pc_;
    int depth = 0;
    constexpr int MAX_FRAMES = 64;
    while (cur_sp != 0 && depth < MAX_FRAMES) {
        std::cerr << "\n  #" << std::dec << depth << " pc=0x" << std::hex << cur_pc
                  << " sp=0x" << cur_sp << std::dec;
        uint64_t* frame_base = (uint64_t*)mmu(cur_sp, sizeof(uint64_t) * 16);
        if (!frame_base) {
            std::cerr << " (frame unreadable at 0x" << std::hex << cur_sp << ")" << std::dec;
            break;
        }
        bool is_signal = frame_is_signal(frame_base[0]);
        // old_r10 / RA 统一在 [1] / [2]（与帧类型无关）。
        uint64_t old_sp   = frame_base[1];
        uint64_t ret_addr = frame_base[2];
        std::cerr << (is_signal ? " [signal]" : "");
        if (old_sp == 0 || old_sp <= cur_sp || ret_addr == 0) {
            // 到达栈底
            break;
        }
        cur_sp = old_sp;
        cur_pc = ret_addr;
        depth++;
    }
    std::cerr << std::dec << std::endl;

    std::cerr << "Current memory maps:" << std::endl;
    for(const auto& map : *maps) {
        // 权限符号化（PF_R=0x4, PF_W=0x2, PF_X=0x1），形如 /proc/<pid>/maps 的 rwx
        char perm[4];
        perm[0] = (map.flags & PF_R) ? 'r' : '-';
        perm[1] = (map.flags & PF_W) ? 'w' : '-';
        perm[2] = (map.flags & PF_X) ? 'x' : '-';
        perm[3] = '\0';
        std::cerr << "  Start: 0x" << std::hex << map.paddr
                  << " End: 0x" << (map.paddr + map.size)
                  << " Size: 0x" << map.size
                  << " Flags: " << perm << std::dec
                  << " Path: " << map.path << std::endl;
    }
    // 内存违例一律视为致命：置 VM_KILLED，把退出码翻成 128+SIGKILL。
    flags.fetch_or(VM_KILLED, std::memory_order_release);
    r(0) = 128 + SIGKILL;
}

int vm::wait_for(const struct timespec* timeout) {
    // 阻塞在 wait_cv 上等待, timeout是相对时间 
    bool has_deadline = timeout != nullptr;
    struct timespec deadline{};
    if(has_deadline) {
        clock_gettime(CLOCK_REALTIME, &deadline);
        deadline.tv_sec += timeout->tv_sec;
        deadline.tv_nsec += timeout->tv_nsec;
        if(deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }
    int rc;
    pthread_mutex_lock(&wait_mutex);
    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(!(f & VM_BLOCKED)) {                 // 被 wakeup(true) 清位
            rc = 0;
            break;
        }
        if(f & (VM_KILLED | VM_SIGNAL_PENDING | VM_STOPPED | VM_DEBUG_STOP)) {
            rc = -EINTR;                        // 交回 safepoint：投递信号 / 退出 / 停止阻塞 / GDB 请求停
            break;
        }
        if(has_deadline) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if(now.tv_sec > deadline.tv_sec ||
               (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                rc = -ETIMEDOUT;
                break;
            }
            pthread_cond_timedwait(&wait_cv, &wait_mutex, &deadline);
        } else {
            // 无 deadline：wakeup() 持锁 broadcast，理论上不丢唤醒；仍保留 1s 滚动超时作
            // spurious-wakeup 兜底（condvar 语义允许假唤醒），每轮重判 flag。
            struct timespec backstop;
            clock_gettime(CLOCK_REALTIME, &backstop);
            backstop.tv_sec += 1;
            pthread_cond_timedwait(&wait_cv, &wait_mutex, &backstop);
        }
    }
    pthread_mutex_unlock(&wait_mutex);
    return rc;
}

void vm::wakeup(bool clear_blocked) {
    pthread_mutex_lock(&wait_mutex);
    if(clear_blocked) {
        flags.fetch_and(~VM_BLOCKED, std::memory_order_release);
    }
    pthread_cond_broadcast(&wait_cv);
    pthread_mutex_unlock(&wait_mutex);
}

bool vm::ld(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    // lddw 是宽指令（占 2 个 bpf_insn 槽），第二个槽也必须在合法映射内
    if(!mmu(pc_ + 2 * sizeof(bpf_insn))) {
        log_mem_violation("lddw second slot", pc_ + 2 * sizeof(bpf_insn));
        return false;
    }
    r(cur->dst_reg) = (uint64_t)(cur+1)->imm << 32 | (uint32_t)cur->imm;
    pc_ += sizeof(bpf_insn);  // 跳过第二槽；run() 循环再 +=sizeof(bpf_insn)，共两槽
    return true;
}

bool vm::ldx(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint64_t target_addr = r(cur->src_reg) + cur->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("read", target_addr);
        return false;
    }
    if((cur->code & 0xe0) == BPF_MEM) {
        switch(cur->code & 0x18) {
        case BPF_DW:
            r(cur->dst_reg) = *(uint64_t*)addr;
            break;
        case BPF_W:
            r(cur->dst_reg) = *(uint32_t*)addr;
            break;
        case BPF_H:
            r(cur->dst_reg) = *(uint16_t*)addr;
            break;
        case BPF_B:
            r(cur->dst_reg) = *(uint8_t*)addr;
            break;
        }
    }else if((cur->code & 0xe0) == BPF_MEMSX) {
        switch(cur->code & 0x18) {
        case BPF_DW:
            return false;
        case BPF_W:
            r(cur->dst_reg) = *(int32_t*)addr;
            break;
        case BPF_H:
            r(cur->dst_reg) = *(int16_t*)addr;
            break;
        case BPF_B:
            r(cur->dst_reg) = *(int8_t*)addr;
            break;
        }
    }else {
        return false;
    }
    return true;
}

bool vm::st(const bpf_insn* cur) {
    uint64_t target_addr = r(cur->dst_reg) + cur->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (cur->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = cur->imm;
        break;
    case BPF_W:
        *(uint32_t*)addr = cur->imm;
        break;
    case BPF_H:
        *(uint16_t*)addr = cur->imm;
        break;
    case BPF_B:
        *(uint8_t*)addr = cur->imm;
        break;
    }
    return true;
}

template<typename T>
static bool do_atomic(T* p, int32_t op, uint64_t& src_reg, uint64_t& r0) {
    T src = (T)src_reg;
    switch(op) {
    case BPF_ADD:                __atomic_fetch_add(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_OR:                 __atomic_fetch_or(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_AND:                __atomic_fetch_and(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XOR:                __atomic_fetch_xor(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_ADD | BPF_FETCH:    src_reg = __atomic_fetch_add(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_OR  | BPF_FETCH:    src_reg = __atomic_fetch_or(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_AND | BPF_FETCH:    src_reg = __atomic_fetch_and(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XOR | BPF_FETCH:    src_reg = __atomic_fetch_xor(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_XCHG:               src_reg = __atomic_exchange_n(p, src, __ATOMIC_SEQ_CST); break;
    case BPF_CMPXCHG: {
        T expected = (T)r0;
        T old = expected;
        __atomic_compare_exchange_n(p, &old, src, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
        r0 = old;
        break;
    }
    default: return false;
    }
    return true;
}

bool vm::stx(const bpf_insn* cur) {
    if((cur->code & 0xe0) == BPF_ATOMIC) {
        uint64_t target_addr = r(cur->dst_reg) + cur->off;
        void* addr = mmu_w(target_addr);
        if(addr == nullptr) {
            log_mem_violation("atomic", target_addr);
            return false;
        }
        switch(cur->code & 0x18) {
        case BPF_DW: return do_atomic((uint64_t*)addr, cur->imm, r(cur->src_reg), r(0));
        case BPF_W:  return do_atomic((uint32_t*)addr, cur->imm, r(cur->src_reg), r(0));
        default:     return false;
        }
    }
    uint64_t target_addr = r(cur->dst_reg) + cur->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (cur->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = r(cur->src_reg);
        break;
    case BPF_W:
        *(uint32_t*)addr = r(cur->src_reg);
        break;
    case BPF_H:
        *(uint16_t*)addr = r(cur->src_reg);
        break;
    case BPF_B:
        *(uint8_t*)addr = r(cur->src_reg);
        break;
    }
    return true;
}

bool vm::alu64(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint64_t src = (cur->code & 0x08) == BPF_X ? r(cur->src_reg) : (uint64_t)(int64_t)cur->imm;
    int64_t signed_src = static_cast<int64_t>(src);
    auto& dst = r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_ADD:
        dst += src;
        break;
    case BPF_SUB:
        dst -= src;
        break;
    case BPF_MUL:
        dst *= src;
        break;
    case BPF_DIV:
        if(cur->off == 0) {
            dst = (src != 0) ? (dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((signed_src == -1 && (int64_t)dst == INT64_MIN) ? INT64_MIN : ((int64_t)dst / signed_src));
        }
        break;
    case BPF_OR:
        dst |= src;
        break;
    case BPF_AND:
        dst &= src;
        break;
    case BPF_LSH:
        dst <<= (src & 0x3f);
        break;
    case BPF_RSH:
        dst >>= (src & 0x3f);
        break;
    case BPF_NEG:
        dst = -(int64_t)dst;
        break;
    case BPF_MOD:
        if(cur->off == 0) {
            dst = (src != 0) ? (dst % src) : dst;
        } else {
            dst = (src == 0) ? dst : ((signed_src == -1 && (int64_t)dst == INT64_MIN) ? 0 : ((int64_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(cur->off == 0) {
            dst = src;
        }else if(cur->off == 8) {
            dst = (int8_t)src;
        }else if(cur->off == 16) {
            dst = (int16_t)src;
        }else if(cur->off == 32) {
            dst = (int32_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int64_t)dst >> (src & 0x3f);
        break;
    case BPF_END:
        switch(cur->imm) {
        case 16:
            dst = __builtin_bswap16((uint16_t)dst);
            break;
        case 32:
            dst = __builtin_bswap32((uint32_t)dst);
            break;
        case 64:
            dst = __builtin_bswap64(dst);
            break;
        default:
            return false;
        }
        break;
    }
    return true;
}

bool vm::alu(const bpf_insn* cur) {
    if(cur->dst_reg >= 10) {
        return false;
    }
    uint32_t src = (cur->code & 0x08) == BPF_X ? (uint32_t)r(cur->src_reg) : cur->imm;
    int32_t signed_src = static_cast<int32_t>(src);
    auto dst = (uint32_t)r(cur->dst_reg);
    switch (cur->code & 0xf0) {
    case BPF_ADD:
        dst += src;
        break;
    case BPF_SUB:
        dst -= src;
        break;
    case BPF_MUL:
        dst *= src;
        break;
    case BPF_DIV:
        if(cur->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst / src) : 0;
        }else {
            dst = (src == 0) ? 0 : ((signed_src == -1 && (int32_t)dst == INT32_MIN) ? INT32_MIN : ((int32_t)dst / signed_src));
        }
        break;
    case BPF_OR:
        dst |= src;
        break;
    case BPF_AND:
        dst &= src;
        break;
    case BPF_LSH:
        dst <<= (src & 0x1f);
        break;
    case BPF_RSH:
        dst >>= (src & 0x1f);
        break;
    case BPF_NEG:
        dst = -(int32_t)dst;
        break;
    case BPF_MOD:
        if(cur->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst % src) : (uint32_t)dst;
        } else {
            dst = (src == 0) ? (uint32_t)dst : ((signed_src == -1 && (int32_t)dst == INT32_MIN) ? 0 : ((int32_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(cur->off == 0) {
            dst = src;
        }else if(cur->off == 8) {
            dst = (int8_t)src;
        }else if(cur->off == 16) {
            dst = (int16_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int32_t)dst >> (src & 0x1f);
        break;
    case BPF_END:
        if((cur->code & 0x08) == BPF_X) {
            // BE: host byte order -> big endian (byte swap on little-endian host)
            switch(cur->imm) {
            case 16: r(cur->dst_reg) = __builtin_bswap16((uint16_t)dst); return true;
            case 32: r(cur->dst_reg) = __builtin_bswap32(dst); return true;
            case 64: r(cur->dst_reg) = __builtin_bswap64(r(cur->dst_reg)); return true;
            default: return false;
            }
        } else {
            // LE: host byte order -> little endian (no-op on little-endian host, just zero-extend)
            switch(cur->imm) {
            case 16: r(cur->dst_reg) = (uint16_t)dst; return true;
            case 32: r(cur->dst_reg) = (uint32_t)dst; return true;
            case 64: return true;
            default: return false;
            }
        }
    }
    // clear high 32 bits
    r(cur->dst_reg) = (uint64_t)dst;
    return true;
}



bool vm::safepoint() {
    // 清 JIT 中止标志：已回到 step/解释器，标志使命完成。
    flags.fetch_and(~VM_JIT_ABORT, std::memory_order_release);
    // 仅在非信号上下文中处理新信号，避免信号处理嵌套
    if(signal_depth == 0) {
        if(!deliver_signal()) {
            //be killed
            return false;
        }
    }

    // 停止等待：VM_STOPPED 由 stop_process（SIGSTOP/SIGTSTP/...）设置。
    pthread_mutex_lock(&wait_mutex);
    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(f & (VM_EXITED | VM_KILLED | VM_BUDGET_EXCEEDED)) {
            pthread_mutex_unlock(&wait_mutex);
            if (f & VM_KILLED) {
                r(0) = 128 + SIGKILL;
            }
            return false;
        }
        if(!(f & VM_STOPPED)) break;
        pthread_cond_wait(&wait_cv, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex);
    // 唤醒后投递停止期间挂起的信号（POSIX：SIGCONT 恢复运行时在返回用户态前 get_signal
    // 投递 pending）。否则停止态收到的 SIGTERM 滞留队列，子进程已先执行到阻塞系统调用
    // （nanosleep），就会卡死。
    return deliver_signal();
}

void vm::debug_park() {
    // GDB 停止的阻塞消费入口：调用方须已置 VM_DEBUG_STOP（见 gdb_server.h 停止模型）。本函数纯
    // 消费——cond_wait 等 GDB continue 清 VM_DEBUG_STOP + wakeup 唤醒，不自己 set flag。
    pthread_mutex_lock(&wait_mutex);
    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(!(f & VM_DEBUG_STOP) || (f & VM_KILLED)) break;
        pthread_cond_wait(&wait_cv, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex);
}

bool vm::step() {
    // JIT hot path: keep executing compiled functions in a tight loop
    for(;;) {
        auto* func = jit->compile(this, pc_);
        if(!func) break;
        jit->stats.jit_func_runs++;
        uint64_t pc_before = pc_;
        ((void(*)(vm*))func->code)(this);
        // JIT 函数返回后，检查是真正的 VM 退出还是可恢复的中断
        // (safepoint, syscall, pc changed, etc.)
        uint32_t f = flags.load(std::memory_order_acquire);
        if(f && !safepoint()) {
            return false;
        }
        // safepoint 已处理信号/stop 等可恢复事件且未请求退出。若期间 pc 被改
        // (longjmp、信号处理、BPF CALL/EXIT 等)，则继续 JIT 循环；否则说明 JIT
        // 在无 flag 的情况下中止（如内存违例），落到解释器单步以报告错误。
        if(pc_ != pc_before) {
            continue;
        }
        break;
    }
    // 解释器执行一条指令
    interp_insns++;
    // 指令计数递增 + 预算检查
    uint64_t cnt = ++insn_count;
    if(options.insn_limit != 0 && cnt >= options.insn_limit) {
        flags.fetch_or(VM_BUDGET_EXCEEDED, std::memory_order_release);
        std::cerr << "Instruction budget exceeded (" << cnt
                  << " >= " << options.insn_limit << ") at PC 0x"
                  << std::hex << pc_ << std::dec << std::endl;
        return false;
    }
    // Safepoint check: flags 非零即需要处理
    uint32_t f = flags.load(std::memory_order_acquire);
    if(f && !safepoint()) {
        return false;
    }
    const bpf_insn* cur = (const bpf_insn*)mmu(pc_);
    if(!cur) {
        log_mem_violation("exec", pc_);
        return false;
    }
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] ", options.sys->id());
        dump(pc_, cur);
    }
    if(flags.load(std::memory_order_acquire) & VM_DEBUG_ATTACHED) {
        // 取指后执行前的停止点：breakpoint 钩子命中断点或消费单步请求时 set VM_DEBUG_STOP，
        // 此处统一判 flag 后 debug_park（停止模型见 gdb_server.h）。
        auto hooks = debug_hooks_.load();
        if(hooks) hooks->breakpoint(this);
        if(flags.load(std::memory_order_acquire) & VM_DEBUG_STOP) debug_park();
    }
    bool ok = false;
    switch(cur->code & 0x07) {
    case BPF_LD:   ok = ld(cur); break;
    case BPF_LDX:  ok = ldx(cur); break;
    case BPF_ST:   ok = st(cur); break;
    case BPF_STX:  ok = stx(cur); break;
    case BPF_ALU:  ok = alu(cur); break;
    case BPF_ALU64: ok = alu64(cur); break;
    case BPF_JMP:  ok = jmp(cur); break;
    case BPF_JMP32: ok = jmp32(cur); break;
    }
    return ok;
}

void vm::addmem(memmap&& memmap) {
    //add by sorted order
    std::lock_guard<std::mutex> lock(*maps_mutex);
    auto it = maps->begin();
    while(it != maps->end() && it->paddr < memmap.paddr) {
        it++;
    }
    maps->insert(it, std::move(memmap));
    flush_tlb();
}

bool vm::unmap(uint64_t addr) {
    std::lock_guard<std::mutex> lock(*maps_mutex);
    for(auto it = maps->begin(); it != maps->end(); ++it) {
        if(addr == it->paddr) {
            maps->erase(it); // unique_ptr destructor handles munmap if owned
            flush_tlb();
            return true;
        }
    }
    return false;
}

void vm::flush_tlb() {
    memset(tlb, 0, sizeof(tlb));
}

void vm::clear_jit_cache() {
    if(jit) jit->clear();
}

void* vm::mmu(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    // TLB fast path (1MB granularity)
    auto& entry = tlb[tlb_index(addr)];
    if(addr >= entry.guest_base && end <= entry.guest_end) {
        return entry.host_base + (addr - entry.guest_base);
    }
    return mmu_slow(addr, size);
}

// 二分查找包含 [addr, addr+size) 的段。调用方须持 maps_mutex。maps 须按 paddr 升序。
std::vector<memmap>::iterator vm::find_map_locked(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    // upper_bound 找第一个 paddr > addr 的段，--it 得到 paddr <= addr 的最大段。
    auto it = std::upper_bound(maps->begin(), maps->end(), addr,
        [](uint64_t a, const memmap& m) { return a < m.paddr; });
    if(it == maps->begin()) return maps->end();  // 所有段 paddr > addr
    --it;
    if(end <= it->paddr + it->size) {            // 含 addr..end（addr>=paddr 已由二分保证）
        return it;
    }
    return maps->end();
}

void* vm::mmu_slow(uint64_t addr, size_t size) {
    auto& entry = tlb[tlb_index(addr)];
    std::lock_guard<std::mutex> lock(*maps_mutex);
    auto it = find_map_locked(addr, size);
    if(it == maps->end()) return nullptr;
    const auto& map = *it;
    entry = {map.paddr, map.paddr + map.size, map.data.get(), map.flags, !!map.cow_data};
    return map.data.get() + (addr - map.paddr);
}

void* vm::mmu_w(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    // TLB fast path (1MB granularity, only when writable and no CoW pending)
    auto& entry = tlb[tlb_index(addr)];
    if(addr >= entry.guest_base && end <= entry.guest_end
       && (entry.flags & PF_W) && !entry.cow) {
        return entry.host_base + (addr - entry.guest_base);
    }
    return mmu_w_slow(addr, size);
}

void* vm::mmu_w_slow(uint64_t addr, size_t size) {
    auto& entry = tlb[tlb_index(addr)];
    std::lock_guard<std::mutex> lock(*maps_mutex);
    auto it = find_map_locked(addr, size);
    if(it == maps->end()) return nullptr;
    auto& map = *it;
    if(!(map.flags & PF_W)) return nullptr;
    if(map.cow_data) { // CoW triggered: copy on write
        if(map.cow_data.use_count() == 1) {
            // 唯一引用，直接偷：解除 cow_data 的所有权，unique_ptr 接管
            std::get_deleter<DataDeleter>(map.cow_data)->owned = false;
            map.cow_data.reset();
            map.data.get_deleter().owned = true;
        } else {
            int prot = PROT_READ | PROT_WRITE;
            if(map.flags & PF_X) prot |= PROT_EXEC;
            auto* p = (unsigned char*)mmap(nullptr, map.size, prot,
                                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(p == MAP_FAILED) return nullptr;
            // 容错：map.data 指向的 host 页可能因 do_mprotect 切分后 host 权限未同步
            // 而处于 PROT_NONE（musl mallocng 先 mmap(PROT_NONE) 再 mprotect(RW)，
            // 切分后未改权限的子段 host 页仍 PROT_NONE）。直接 memcpy 会 host SIGSEGV。
            // 临时开读权限拷贝，然后恢复成与 guest flags 一致的 host 权限。
            // mprotect 失败则源页不可读，无法拷贝 —— 释放新页并返回 nullptr（让调用方
            // 报 EFAULT），绝不把未初始化的 p 当 CoW 结果交出去（否则静默数据损坏）。
            if (mprotect(map.data.get(), map.size, PROT_READ) != 0) {
                munmap(p, map.size);
                return nullptr;
            }
            memcpy(p, map.data.get(), map.size);
            int orig_prot = PROT_NONE;
            if (map.flags & PF_R) orig_prot |= PROT_READ;
            if (map.flags & PF_W) orig_prot |= PROT_WRITE;
            if (map.flags & PF_X) orig_prot |= PROT_EXEC;
            mprotect(map.data.get(), map.size, orig_prot);
            map.cow_data.reset();
            map.set_data(p, map.size);
        }
        flush_tlb();
    }
    // Fill TLB after CoW is resolved
    entry = {map.paddr, map.paddr + map.size, map.data.get(), map.flags, !!map.cow_data};
    return map.data.get() + (addr - map.paddr);
}

void vm::dump_stats() const {
    if (!getenv("BPF_DEBUG")) return;
    fprintf(stderr, "[BPF] 执行指令数: %" PRIu64 "\n", insn_count);
    fprintf(stderr, "[BPF] 解释器执行指令数: %" PRIu64 "\n", interp_insns);
    auto& s = jit->stats;
    if (s.jit_compiles) {
        fprintf(stderr, "[BPF] JIT编译函数数: %" PRIu64 "\n", s.jit_compiles);
        fprintf(stderr, "[BPF] JIT编译指令数: %" PRIu64 "\n", s.jit_compiled_insns);
        fprintf(stderr, "[BPF] JIT执行函数次数: %" PRIu64 "\n", s.jit_func_runs);
        fprintf(stderr, "[BPF] 编译时平均函数大小: %.1f条\n",
                (double)s.jit_compiled_insns / s.jit_compiles);
        fprintf(stderr, "[BPF] 编译耗时: %.1fms\n", s.compile_ns / 1e6);
    }
}

uint64_t vm::run() {
    if(!jit) jit = std::make_unique<JitCompilerImpl>();
    if(options.sys) options.sys->init(shared_from_this());
    while(step()) {
        pc_ += sizeof(bpf_insn);
    }
    if(options.sys) options.sys->fini(shared_from_this());
    dump_stats();
    if(flags.load(std::memory_order_acquire) & VM_BUDGET_EXCEEDED) {
        r(0) = 255;
    }
    flags.fetch_or(VM_EXITED, std::memory_order_release);
    pthread_cond_broadcast(&wait_cv);
    // 释放本 vm 的镜像引用：僵尸态发布（run 已退、vm 仍活）——ExeLinkGen 判空报
    // ENOENT；共享该 image 的 fork 子 vm 不受影响（引用计数，对齐 exe_file）。
    set_image(nullptr);
    return r(0);
}

uint64_t vm::run(const vmOptions* options, const ElfLoadInfo& info) {
    this->options = *options;
    insn_count = 0;
    interp_insns = 0;
    uint64_t entry = 0;
    if(auto img = image()) entry = img->entry;
    if(options->verbose) {
        printf("entry: 0x%lx\n", (unsigned long)entry);
    }

    // setup_stack 接收 map（key->value），内部拼成 "KEY=VALUE" 写入栈。
    if(!setup_stack(options->argv, options->envp, info)) {
        return 0;
    }
    flags.fetch_and(~(VM_EXITED | VM_KILLED), std::memory_order_release);
    pc_ = entry;
    if(!mmu(pc_)) {
        std::cerr << "[run] pc is null after mmu(entry)\n";
        return 0;
    }
    push_frame(0);
    return run();
}

bool vm::setup_stack(const std::vector<std::string>& argv,
                     const std::map<std::string, std::string>& envp,
                     const ElfLoadInfo& info) {
    unsigned char* stack_base = (unsigned char*)mmu(STACK_BASE);
    if(stack_base == nullptr) {
        unsigned char* data = (unsigned char*)mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(data == MAP_FAILED) {
            std::cerr << "Failed to allocate stack" << std::endl;
            return false;
        }
        memmap stack_memmap;
        stack_memmap.set_data(data, STACK_SIZE);
        stack_memmap.size = STACK_SIZE;
        stack_memmap.paddr = STACK_BASE;
        stack_memmap.flags = PF_W;
        stack_memmap.path = "<stack>";
        addmem(std::move(stack_memmap));
        stack_base = data;
    }

    reg[10] = STACK_BASE + STACK_SIZE - 8;

    // 哨兵：在初始 r10 处写一个合法 frame[0]，模拟"调用者帧"，给_start的局部变量用。
    // 用普通帧 size；total_len = stack_limit（无 alloca）。
    *(uint64_t*)mmu_w(reg[10]) = frame_flags_make(false, options.stack_limit);

    if(options.raw_stack) {
        return true;
    }

    size_t strings_bytes = 0;
    for(const auto& arg : argv) {
        strings_bytes += arg.size() + 1;
    }
    // 每个 env 项在栈上写作 "KEY=VALUE\0"：key + '=' + val + '\0'。
    for(const auto& [k, val] : envp) {
        strings_bytes += k.size() + 1 + val.size() + 1;
    }

    // 附加 auxv 载荷字符串：
    //   - AT_PLATFORM 指向的 "bpf"（含 '\0'）
    //   - AT_RANDOM 指向的 16 字节随机数据
    static const char kPlatform[] = "bpf";
    const size_t platform_bytes = sizeof(kPlatform); // 含 '\0'
    constexpr size_t kRandomBytes = 16;

    // auxv 条目（type/val 成对的 uint64）；指针型字段稍后回填。
    struct AuxEntry { uint64_t type; uint64_t val; };
    AuxEntry auxv[] = {
        {AT_PAGESZ,   4096},
        {AT_CLKTCK,   100},
        {AT_UID,      0},
        {AT_EUID,     0},
        {AT_GID,      0},
        {AT_EGID,     0},
        {AT_SECURE,   0},
        {AT_BASE,     info.ldso_base},  // 动态链接器加载基址（ldso 自举用）；静态为 0
        {AT_PHDR,     info.phdr},   // 主程序 program header table 运行时地址
        {AT_PHENT,    info.phent},  // 单个 phdr 大小
        {AT_PHNUM,    info.phnum},  // phdr 个数
        {AT_ENTRY, info.app_entry ? info.app_entry : info.entry},  // 入口点（ldso 模式为主程序入口，否则=info.entry）
        {AT_PLATFORM, 0},   // 回填
        {AT_EXECFN,   0},   // 回填
        {AT_RANDOM,   0},   // 回填
        {AT_NULL,     0},
    };
    const size_t aux_qwords = sizeof(auxv) / sizeof(*auxv) * 2;

    // Stack layout at STACK_BASE (low to high)：
    //   argc
    //   argv[0..argc-1] 指针
    //   NULL
    //   envp[0..envc-1] 指针
    //   NULL
    //   auxv[]  （每个条目 2 x uint64，以 {AT_NULL,0} 结尾）
    //   argv/env 字符串
    //   "bpf\0" 平台串
    //   16 字节随机数据（AT_RANDOM）
    size_t header_qwords = 1 + (argv.size() + 1) + (envp.size() + 1) + aux_qwords;
    size_t header_bytes = header_qwords * sizeof(uint64_t);
    size_t total_bytes = header_bytes + strings_bytes + platform_bytes + kRandomBytes;
    if(total_bytes > STACK_SIZE) {
        std::cerr << "Stack arguments exceed stack size" << std::endl;
        return false;
    }

    uint64_t* header = (uint64_t*)stack_base;
    header[0] = argv.size();
    size_t cursor = header_bytes;

    for(size_t i = 0; i < argv.size(); i++) {
        size_t len = argv[i].size() + 1;
        memcpy(stack_base + cursor, argv[i].c_str(), len);
        header[1 + i] = STACK_BASE + cursor;
        cursor += len;
    }
    header[1 + argv.size()] = 0;

    size_t env_base = 1 + (argv.size() + 1);
    size_t env_idx = 0;
    for(const auto& [k, val] : envp) {
        int n = sprintf(reinterpret_cast<char*>(stack_base + cursor), "%s=%s", k.c_str(), val.c_str());
        header[env_base + env_idx] = STACK_BASE + cursor;
        cursor += n + 1;  // +1 for '\0'（sprintf 返回不含 '\0'）
        env_idx++;
    }
    header[env_base + envp.size()] = 0;

    // auxv 紧跟在 envp 的 NULL 之后。
    size_t aux_base = env_base + envp.size() + 1;

    // AT_PLATFORM 指向的 "bpf\0"
    size_t platform_off = cursor;
    memcpy(stack_base + cursor, kPlatform, platform_bytes);
    cursor += platform_bytes;

    // AT_EXECFN：复用 argv[0] 的指针；无 argv 时回退到 AT_PLATFORM 串。
    uint64_t execfn_ptr = (!argv.empty()) ? header[1] : (STACK_BASE + platform_off);

    // AT_RANDOM 指向的 16 字节随机数据
    ssize_t got = ::syscall(SYS_getrandom, stack_base + cursor, kRandomBytes, 0);
    if(got != (ssize_t)kRandomBytes) {
        std::cerr << "Failed to get random bytes for AT_RANDOM" << std::endl;
        return false;
    }

    // 写入 auxv 条目并回填指针型字段
    for(size_t i = 0; i < sizeof(auxv) / sizeof(*auxv); ++i) {
        uint64_t type = auxv[i].type;
        uint64_t val  = auxv[i].val;
        switch(type) {
        case AT_PLATFORM:
            val = STACK_BASE + platform_off;
            break;
        case AT_EXECFN:
            val = execfn_ptr;
            break;
        case AT_RANDOM:
            val = STACK_BASE + cursor;
            break;
        default:
            break;
        }
        header[aux_base + i * 2]     = type;
        header[aux_base + i * 2 + 1] = val;
    }

    reg[1] = STACK_BASE;
    return true;
}
