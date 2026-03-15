//
// Created by chouryzhou on 24-10-28.
//

#include "insn.h"
#include <iostream>

#include <libelf.h>
#include <gelf.h>
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

memmap::~memmap() {
    if(data == nullptr || data == MAP_FAILED) {
        return;
    }
    if(owned) {
        munmap(data, size);
    }
}

memmap memmap::static_map(void* addr, size_t size, uint64_t paddr) {
    memmap map;
    map.data = (unsigned char*)addr;
    map.size = size;
    map.paddr = paddr;
    map.flags = PF_R;
    map.owned = false;
    return map;
}



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
    pthread_mutex_init(&exit_mutex, nullptr);
    pthread_cond_init(&exit_cv, nullptr);
    memset(reg, 0, sizeof(reg));
}

vm::~vm() {
    pthread_cond_destroy(&exit_cv);
    pthread_mutex_destroy(&exit_mutex);
}

std::shared_ptr<vm> vm::create() {
    return std::make_shared<vm>(Token{});
}

uint64_t vm::load_elf(const char* elf_file_path) {
    uint64_t entry = 0;
    int fd = -1;
    Elf* elf = nullptr;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "Failed to initialize libelf: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    fd = open(elf_file_path, O_RDONLY);
    if(fd < 0) {
        std::cerr << "Failed to open: "<<elf_file_path<<": " << strerror(errno) << std::endl;
        goto out;
    }

    elf = elf_begin(fd, ELF_C_READ, nullptr);
    if(elf == nullptr) {
        std::cerr << "Failed to open ELF file: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    if(elf_kind(elf) != ELF_K_ELF) {
        std::cerr << "Not an ELF file" << std::endl;
        goto out;
    }

    GElf_Ehdr ehdr;
    if(gelf_getehdr(elf, &ehdr) != &ehdr) {
        std::cerr << "Failed to get ELF header: " << elf_errmsg(-1) << std::endl;
        goto out;
    }

    if(ehdr.e_type != ET_EXEC) {
        std::cerr << "Not an executable ELF file: " << elf_file_path << " type: " << ehdr.e_type << std::endl;
        goto out;
    }

    if(ehdr.e_machine != 0xf7) {
        std::cerr << "Not an bpf ELF file: " << elf_file_path << " machine: " << ehdr.e_machine << std::endl;
        goto out;
    }

    for(size_t i = 0; i < ehdr.e_phnum; i++) {
        GElf_Phdr phdr;
        if(gelf_getphdr(elf, i, &phdr) != &phdr) {
            std::cerr << "Failed to get program header: " << elf_errmsg(-1) << std::endl;
            goto out;
        }
        if(phdr.p_type != PT_LOAD) {
            continue;
        }

        memmap map;
        map.paddr = phdr.p_vaddr;
        map.size = phdr.p_memsz;
        if(phdr.p_flags & PF_W) {
            map.data = (unsigned char*)mmap(nullptr, map.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if(map.data == MAP_FAILED) {
                std::cerr << "Failed to mmap section: " << strerror(errno) << std::endl;
                goto out;
            }
            if(pread(fd, map.data, phdr.p_filesz, phdr.p_offset) != (ssize_t)phdr.p_filesz) {
                std::cerr << "Failed to read section: " << strerror(errno) << std::endl;
                goto out;
            }
        }else {
            map.data = (unsigned char*)mmap(nullptr, map.size, PROT_READ, MAP_PRIVATE, fd, phdr.p_offset);
            if(map.data == MAP_FAILED) {
                std::cerr << "Failed to mmap section: " << strerror(errno) << std::endl;
                goto out;
            }
        }
        map.flags = phdr.p_flags;
        addmem(std::move(map));
    }

    entry = ehdr.e_entry;

out:
    if(elf != nullptr) {
        elf_end(elf);
    }
    if(fd >= 0) {
        close(fd);
    }
    return entry;
}

/*
 * Stack Frame Layout:
 *
 * Normal Frame (64 bytes):
 * +------------------+
 * | flags (0)        | frame_base[0]
 * +------------------+
 * | r6               | frame_base[1]
 * | r7               | frame_base[2]
 * | r8               | frame_base[3]
 * | r9               | frame_base[4]
 * +------------------+
 * | old_r10 (SP)     | frame_base[5]
 * +------------------+
 * | return_address   | frame_base[6]
 * +------------------+
 * | unused           | frame_base[7]
 * +------------------+
 *
 * Signal Frame (128 bytes):
 * +------------------+
 * | flags (1)        | frame_base[0]
 * +------------------+
 * | r0               | frame_base[1]
 * | r1               | frame_base[2]
 * | r2               | frame_base[3]
 * | r3               | frame_base[4]
 * | r4               | frame_base[5]
 * | r5               | frame_base[6]
 * | r6               | frame_base[7]
 * | r7               | frame_base[8]
 * | r8               | frame_base[9]
 * | r9               | frame_base[10]
 * +------------------+
 * | old_r10 (SP)     | frame_base[11]
 * +------------------+
 * | return_address   | frame_base[12]
 * +------------------+
 * | unused (3 slots) | frame_base[13..15]
 * +------------------+
 */
bool vm::push_frame(uint64_t return_addr, bool is_signal) {
    uint32_t frame_size = is_signal ? 128 : 64;
    if(r(10) - STACK_LIMIT - frame_size < STACK_BASE) {
        log_mem_violation("stack overflow", r(10));
        return false;
    }
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] PUSH sp=%lx ret=%lx sig=%d size=%d\n", 
            options.sys->id(), r(10), return_addr, is_signal, frame_size);
    }
    uint64_t sp = r(10) - STACK_LIMIT;
    uint64_t frame_base_addr = sp - frame_size;
    uint64_t* frame_base = (uint64_t*)mmu(frame_base_addr);
    if(!frame_base) {
        log_mem_violation("stack access", frame_base_addr);
        return false;
    }

    frame_base[0] = is_signal ? 1 : 0; // flags
    if (is_signal) {
        signal_depth++;
        frame_base[1] = r(0);
        frame_base[2] = r(1);
        frame_base[3] = r(2);
        frame_base[4] = r(3);
        frame_base[5] = r(4);
        frame_base[6] = r(5);
        frame_base[7] = r(6);
        frame_base[8] = r(7);
        frame_base[9] = r(8);
        frame_base[10] = r(9);
        frame_base[11] = r(10);
        frame_base[12] = return_addr;
    } else {
        frame_base[1] = r(6);
        frame_base[2] = r(7);
        frame_base[3] = r(8);
        frame_base[4] = r(9);
        frame_base[5] = r(10);
        frame_base[6] = return_addr;
    }

    r(10) = frame_base_addr;
    return true;
}

uint64_t vm::pop_frame() {
    uint64_t sp = r(10);
    uint64_t* frame_base = (uint64_t*)mmu(sp);
    if(!frame_base) return 0;

    uint64_t old_sp;
    uint64_t ret_addr;
    bool is_signal = frame_base[0] != 0;
    if (is_signal) {
        signal_depth--;
        r(0) = frame_base[1];
        r(1) = frame_base[2];
        r(2) = frame_base[3];
        r(3) = frame_base[4];
        r(4) = frame_base[5];
        r(5) = frame_base[6];
        r(6) = frame_base[7];
        r(7) = frame_base[8];
        r(8) = frame_base[9];
        r(9) = frame_base[10];
        old_sp = frame_base[11];
        ret_addr = frame_base[12];
    } else {
        r(6) = frame_base[1];
        r(7) = frame_base[2];
        r(8) = frame_base[3];
        r(9) = frame_base[4];
        old_sp = frame_base[5];
        ret_addr = frame_base[6];
    }

    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] [STACK] POP sp=%lx new_sp=%lx ret=%lx sig=%d\n", 
            options.sys->id(), sp, old_sp, ret_addr, is_signal);
    }
    r(10) = old_sp;
    return ret_addr;
}

bool vm::jmp() {
    uint64_t src = (pc->code & 0x08) == BPF_X ? r(pc->src_reg) : pc->imm;
    switch (pc->code & 0xf0) {
    case BPF_JA:
        pc += pc->off;
        break;
    case BPF_JEQ:
        if (r(pc->dst_reg) == src) {
            pc += pc->off;
        }
        break;
    case BPF_JGT:
        if (r(pc->dst_reg) > src) {
            pc += pc->off;
        }
        break;
    case BPF_JGE:
        if (r(pc->dst_reg) >= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSET:
        if (r(pc->dst_reg) & src) {
            pc += pc->off;
        }
        break;
    case BPF_JNE:
        if (r(pc->dst_reg) != src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGT:
        if ((int64_t)r(pc->dst_reg) > (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGE:
        if ((int64_t)r(pc->dst_reg) >= (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_CALL:
        if((pc->code & 0x08) == BPF_X) {
            if(!push_frame(unmmu(pc + 1))) {
                return false;
            }
            uint64_t target = r(pc->dst_reg);
            pc = (const bpf_insn*)mmu(target);
            if(pc == nullptr) {
                log_mem_violation("call", target);
                return false;
            }
            pc--;
        }else if(pc->src_reg == 0) {
            return do_syscall(pc->imm);
        }else if(pc->src_reg == 1) {
            if(!push_frame(unmmu(pc + 1))) {
                return false;
            }
            pc += pc->imm;
        }
        break;
    case BPF_EXIT:
    {
        uint64_t ret = pop_frame();
        if(ret == 0) {
            //到栈底了
            return false;
        }
        pc = (const bpf_insn*)mmu(ret);
        if(pc == nullptr) {
            log_mem_violation("return", ret);
            return false;
        }
        pc--; // counter loop increment
        break;
    }
    case BPF_JLT:
        if (r(pc->dst_reg) < src) {
            pc += pc->off;
        }
        break;
    case BPF_JLE:
        if (r(pc->dst_reg) <= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLT:
        if ((int64_t)r(pc->dst_reg) < (int64_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLE:
        if ((int64_t)r(pc->dst_reg) <= (int64_t)src) {
            pc += pc->off;
        }
        break;
    }
    return true;
}

bool vm::jmp32() {
    uint32_t src = (pc->code & 0x08) == BPF_X ? (uint32_t)r(pc->src_reg) : pc->imm;
    auto dst = (uint32_t)r(pc->dst_reg);
    switch (pc->code & 0xf0) {
    case BPF_JA:
        pc += pc->imm;
        break;
    case BPF_JEQ:
        if (dst == src) {
            pc += pc->off;
        }
        break;
    case BPF_JGT:
        if (dst > src) {
            pc += pc->off;
        }
        break;
    case BPF_JGE:
        if (dst >= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSET:
        if (dst & src) {
            pc += pc->off;
        }
        break;
    case BPF_JNE:
        if (dst != src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGT:
        if ((int32_t)dst > (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSGE:
        if ((int32_t)dst >= (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_CALL:
    case BPF_EXIT:
        return false;
    case BPF_JLT:
        if (dst < src) {
            pc += pc->off;
        }
        break;
    case BPF_JLE:
        if (dst <= src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLT:
        if ((int32_t)dst < (int32_t)src) {
            pc += pc->off;
        }
        break;
    case BPF_JSLE:
        if ((int32_t)dst <= (int32_t)src) {
            pc += pc->off;
        }
        break;
    }
    return true;
}


void vm::log_mem_violation(const char* type, uint64_t addr) {
    std::cerr << "Memory access violation at PC 0x" << std::hex << unmmu(pc)
              << ": invalid " << type << " at address 0x" << addr << std::dec << std::endl;
    std::cerr << "Current memory maps:" << std::endl;
    for(const auto& map : maps) {
        std::cerr << "  Start: 0x" << std::hex << map.paddr
                  << " End: 0x" << (map.paddr + map.size)
                  << " Size: 0x" << map.size
                  << " Flags: " << map.flags << std::dec << std::endl;
    }
}

void vm::wakeup() {
    pthread_cond_broadcast(&exit_cv);
}



bool vm::ld() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    r(pc->dst_reg) = (uint64_t)(pc+1)->imm << 32 | (uint32_t)pc->imm;
    pc++;
    return true;
}

bool vm::ldx() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint64_t target_addr = r(pc->src_reg) + pc->off;
    void* addr = mmu(target_addr);
    if (addr == nullptr) {
        log_mem_violation("read", target_addr);
        return false;
    }
    if((pc->code & 0xe0) == BPF_MEM) {
        switch(pc->code & 0x18) {
        case BPF_DW:
            r(pc->dst_reg) = *(uint64_t*)addr;
            break;
        case BPF_W:
            r(pc->dst_reg) = *(uint32_t*)addr;
            break;
        case BPF_H:
            r(pc->dst_reg) = *(uint16_t*)addr;
            break;
        case BPF_B:
            r(pc->dst_reg) = *(uint8_t*)addr;
            break;
        }
    }else if((pc->code & 0xe0) == BPF_MEMSX) {
        switch(pc->code & 0x18) {
        case BPF_DW:
            return false;
        case BPF_W:
            r(pc->dst_reg) = *(int32_t*)addr;
            break;
        case BPF_H:
            r(pc->dst_reg) = *(int16_t*)addr;
            break;
        case BPF_B:
            r(pc->dst_reg) = *(int8_t*)addr;
            break;
        }
    }else {
        return false;
    }
    return true;
}

bool vm::st() {
    uint64_t target_addr = r(pc->dst_reg) + pc->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (pc->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = pc->imm;
        break;
    case BPF_W:
        *(uint32_t*)addr = pc->imm;
        break;
    case BPF_H:
        *(uint16_t*)addr = pc->imm;
        break;
    case BPF_B:
        *(uint8_t*)addr = pc->imm;
        break;
    }
    return true;
}

template<typename T>
static bool do_atomic(T* p, int32_t op, uint64_t& src_reg, uint64_t& r0) {
    T src = (T)src_reg;
    T old = *p;
    switch(op) {
    case BPF_ADD:                *p = old + src; break;
    case BPF_OR:                 *p = old | src; break;
    case BPF_AND:                *p = old & src; break;
    case BPF_XOR:                *p = old ^ src; break;
    case BPF_ADD | BPF_FETCH:    *p = old + src; src_reg = old; break;
    case BPF_OR  | BPF_FETCH:    *p = old | src; src_reg = old; break;
    case BPF_AND | BPF_FETCH:    *p = old & src; src_reg = old; break;
    case BPF_XOR | BPF_FETCH:    *p = old ^ src; src_reg = old; break;
    case BPF_XCHG:               *p = src; src_reg = old; break;
    case BPF_CMPXCHG:
        if(old == (T)r0) { *p = src; }
        r0 = old;
        break;
    default: return false;
    }
    return true;
}

bool vm::stx() {
    if((pc->code & 0xe0) == BPF_ATOMIC) {
        uint64_t target_addr = r(pc->dst_reg) + pc->off;
        void* addr = mmu_w(target_addr);
        if(addr == nullptr) {
            log_mem_violation("atomic", target_addr);
            return false;
        }
        switch(pc->code & 0x18) {
        case BPF_DW: return do_atomic((uint64_t*)addr, pc->imm, r(pc->src_reg), r(0));
        case BPF_W:  return do_atomic((uint32_t*)addr, pc->imm, r(pc->src_reg), r(0));
        default:     return false;
        }
    }
    uint64_t target_addr = r(pc->dst_reg) + pc->off;
    void* addr = mmu_w(target_addr);
    if (addr == nullptr) {
        log_mem_violation("write", target_addr);
        return false;
    }
    switch (pc->code & 0x18) {
    case BPF_DW:
        *(uint64_t*)addr = r(pc->src_reg);
        break;
    case BPF_W:
        *(uint32_t*)addr = r(pc->src_reg);
        break;
    case BPF_H:
        *(uint16_t*)addr = r(pc->src_reg);
        break;
    case BPF_B:
        *(uint8_t*)addr = r(pc->src_reg);
        break;
    }
    return true;
}

bool vm::alu64() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint64_t src = (pc->code & 0x08) == BPF_X ? r(pc->src_reg) : (uint64_t)(int64_t)pc->imm;
    int64_t signed_src = static_cast<int64_t>(src);
    auto& dst = r(pc->dst_reg);
    switch (pc->code & 0xf0) {
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
        if(pc->off == 0) {
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
        if(pc->off == 0) {
            dst = (src != 0) ? (dst % src) : dst;
        } else {
            dst = (src == 0) ? dst : ((signed_src == -1 && (int64_t)dst == INT64_MIN) ? 0 : ((int64_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(pc->off == 0) {
            dst = src;
        }else if(pc->off == 8) {
            dst = (int8_t)src;
        }else if(pc->off == 16) {
            dst = (int16_t)src;
        }else if(pc->off == 32) {
            dst = (int32_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int64_t)dst >> (src & 0x3f);
        break;
    case BPF_END:
        switch(pc->imm) {
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

bool vm::alu() {
    if(pc->dst_reg >= 10) {
        return false;
    }
    uint32_t src = (pc->code & 0x08) == BPF_X ? (uint32_t)r(pc->src_reg) : pc->imm;
    int32_t signed_src = static_cast<int32_t>(src);
    auto dst = (uint32_t)r(pc->dst_reg);
    switch (pc->code & 0xf0) {
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
        if(pc->off == 0) {
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
        if(pc->off == 0) {
            dst = (src != 0) ? ((uint32_t)dst % src) : (uint32_t)dst;
        } else {
            dst = (src == 0) ? (uint32_t)dst : ((signed_src == -1 && (int32_t)dst == INT32_MIN) ? 0 : ((int32_t)dst % signed_src));
        }
        break;
    case BPF_XOR:
        dst ^= src;
        break;
    case BPF_MOV:
        if(pc->off == 0) {
            dst = src;
        }else if(pc->off == 8) {
            dst = (int8_t)src;
        }else if(pc->off == 16) {
            dst = (int16_t)src;
        }
        break;
    case BPF_ARSH:
        dst = (int32_t)dst >> (src & 0x1f);
        break;
    case BPF_END:
        if((pc->code & 0x08) == BPF_X) {
            // BE: host byte order -> big endian (byte swap on little-endian host)
            switch(pc->imm) {
            case 16: r(pc->dst_reg) = __builtin_bswap16((uint16_t)dst); return true;
            case 32: r(pc->dst_reg) = __builtin_bswap32(dst); return true;
            case 64: r(pc->dst_reg) = __builtin_bswap64(r(pc->dst_reg)); return true;
            default: return false;
            }
        } else {
            // LE: host byte order -> little endian (no-op on little-endian host, just zero-extend)
            switch(pc->imm) {
            case 16: r(pc->dst_reg) = (uint16_t)dst; return true;
            case 32: r(pc->dst_reg) = (uint32_t)dst; return true;
            case 64: return true;
            default: return false;
            }
        }
    }
    // clear high 32 bits
    r(pc->dst_reg) = (uint64_t)dst;
    return true;
}



bool vm::step() {
    if(signal_depth == 0) {
        if(!options.sys->handle_signals(this)) {
            //be killed
            return false;
        }
    }

    while(true) {
        uint32_t f = flags.load(std::memory_order_acquire);
        if(f & (VM_EXITED | VM_KILLED)) {
            if (f & VM_KILLED) {
                r(0) = 128 + SIGKILL;
            }
            return false;
        }
        if(!(f & VM_STOPPED)) break;
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100000000L; // 100ms
        if(ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&exit_mutex);
        pthread_cond_timedwait(&exit_cv, &exit_mutex, &ts);
        pthread_mutex_unlock(&exit_mutex);
    }
    uint64_t addr = unmmu(pc);
    if(options.verbose) {
        std::lock_guard<std::mutex> lock(log_mutex);
        printf("[#%d] ", options.sys->id());
        dump(addr, pc);
    }
    if(options.step_run || (options.breakpoint && options.breakpoint == addr)) {
#if defined(__x86_64__) || defined(__i386__)
        asm volatile("int3");
#elif defined(__aarch64__)
        asm volatile("brk #0");
#endif
    }
    switch(pc->code & 0x07) {
    case BPF_LD:
        return ld();
    case BPF_LDX:
        return ldx();
    case BPF_ST:
        return st();
    case BPF_STX:
        return stx();
    case BPF_ALU:
        return alu();
    case BPF_ALU64:
        return alu64();
    case BPF_JMP:
        return jmp();
    case BPF_JMP32:
        return jmp32();
    }
    return false;
}

void vm::addmem(memmap&& memmap) {
    //add by sorted order
    auto it = maps.begin();
    while(it != maps.end() && it->paddr < memmap.paddr) {
        it++;
    }
    maps.insert(it, std::move(memmap));
}

void* vm::unmap(uint64_t addr) {
    for(auto it = maps.begin(); it != maps.end(); ++it) {
        if(addr == it->paddr) {
            void* data = it->data;
            it->data = nullptr;
            maps.erase(it);
            return data;
        }
    }
    return nullptr;
}

void* vm::mmu(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    for(const auto& map: maps) {
        if(addr >= map.paddr && end <= map.paddr + map.size) {
            return map.data + (addr - map.paddr);
        }
    }
    return nullptr;
}

void* vm::mmu_w(uint64_t addr, size_t size) {
    uint64_t end = addr + size;
    if(end < addr) return nullptr; // overflow
    for(const auto& map: maps) {
        if(addr >= map.paddr && end <= map.paddr + map.size) {
            if(!(map.flags & PF_W)) return nullptr;
            return map.data + (addr - map.paddr);
        }
    }
    return nullptr;
}

uint64_t vm::unmmu(const void* addr) {
    for(const auto& map: maps) {
        if(addr >= map.data && addr < map.data + map.size) {
            return map.paddr + ((unsigned char*)addr - map.data);
        }
    }
    return 0;
}

uint64_t vm::run() {
    if(options.sys) options.sys->init(shared_from_this());
    while(step()) {
        pc++;
    }
    if(options.sys) options.sys->fini(shared_from_this());
    flags.fetch_or(VM_EXITED, std::memory_order_release);
    pthread_cond_broadcast(&exit_cv);
    return r(0);
}

uint64_t vm::run(const vmOptions* options) {
    this->options = *options;
    if(options->verbose) {
        printf("entry: 0x%lx\n", options->entry);
    }

    if(!setup_stack(options->argv, options->envp)) {
        return 0;
    }
    flags.fetch_and(~(VM_EXITED | VM_KILLED), std::memory_order_release);
    pc = (const bpf_insn*)mmu(options->entry);
    push_frame(0);
    return run();
}

bool vm::wait_for_exit(int timeout_ms) {
    if(flags.load(std::memory_order_acquire) & VM_EXITED) {
        return true;
    }
    pthread_mutex_lock(&exit_mutex);
    if(!(flags.load(std::memory_order_acquire) & VM_EXITED)) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += timeout_ms / 1000;
        ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
        if(ts.tv_nsec >= 1000000000L) {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1000000000L;
        }
        pthread_cond_timedwait(&exit_cv, &exit_mutex, &ts);
    }
    pthread_mutex_unlock(&exit_mutex);
    return (flags.load(std::memory_order_acquire) & VM_EXITED) != 0;
}

bool vm::setup_stack(const std::vector<std::string>& argv, const std::vector<std::string>& envp) {
    unsigned char* stack_base = (unsigned char*)mmu(STACK_BASE);
    if(stack_base == nullptr) {
        unsigned char* data = (unsigned char*)mmap(nullptr, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(data == MAP_FAILED) {
            std::cerr << "Failed to allocate stack" << std::endl;
            return false;
        }
        memmap stack_memmap;
        stack_memmap.data = data;
        stack_memmap.size = STACK_SIZE;
        stack_memmap.paddr = STACK_BASE;
        stack_memmap.flags = PF_W;
        addmem(std::move(stack_memmap));
        stack_base = data;
    }

    reg[10] = STACK_BASE + STACK_SIZE - 8;

    if(options.raw_stack) {
        return true;
    }

    size_t strings_bytes = 0;
    for(const auto& arg : argv) {
        strings_bytes += arg.size() + 1;
    }
    for(const auto& env : envp) {
        strings_bytes += env.size() + 1;
    }

    // Stack layout at STACK_BASE (low to high):
    // +------------------+
    // | argc             |
    // +------------------+
    // | argv[0] ptr       |
    // | argv[1] ptr       |
    // | ...               |
    // | argv[argc-1] ptr  |
    // | NULL              |
    // +------------------+
    // | envp[0] ptr       |
    // | envp[1] ptr       |
    // | ...               |
    // | envp[envc-1] ptr  |
    // | NULL              |
    // +------------------+
    // | argv/env strings  |
    // +------------------+
    size_t header_qwords = 1 + (argv.size() + 1) + (envp.size() + 1);
    size_t header_bytes = header_qwords * sizeof(uint64_t);
    size_t total_bytes = header_bytes + strings_bytes;
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
    for(size_t i = 0; i < envp.size(); i++) {
        size_t len = envp[i].size() + 1;
        memcpy(stack_base + cursor, envp[i].c_str(), len);
        header[env_base + i] = STACK_BASE + cursor;
        cursor += len;
    }
    header[env_base + envp.size()] = 0;

    reg[1] = STACK_BASE;
    return true;
}
