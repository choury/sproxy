//
// Created by chouryzhou on 24-10-28.
//

#ifndef INSN_H
#define INSN_H
#include "elf_loader.h"

#include <list>
#include <map>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <string>
#include <unordered_set>
#include <vector>
#include <sys/mman.h>

extern std::mutex log_mutex;

#define STACK_SIZE (8 * 1024 * 1024)
#define STACK_BASE 0x10000000ULL

// 栈帧 frame_base[0] 的编码：
//   bit 0..31 : 本函数栈帧总长度 = stack_limit + alloca_len
//   bit    32 : is_signal（1=信号帧 128B / 0=普通帧 64B）；其余高位保留。
// 帧布局详见 insn.cpp 的 Stack Frame Layout。
constexpr uint32_t NORMAL_FRAME_SIZE = 64;
constexpr uint32_t SIGNAL_FRAME_SIZE = 128;
#define FRAME_FLAG_SIGNAL  (1ull << 32)
#define FRAME_LEN_MASK     0xFFFFFFFFull          // 低 32 位 = stack_limit + alloca_len
#define frame_flags_make(is_sig, total_len) \
    ((uint64_t)(((uint64_t)(total_len) & FRAME_LEN_MASK) | ((is_sig) ? FRAME_FLAG_SIGNAL : 0)))
#define frame_is_signal(flags0)  (((flags0) & FRAME_FLAG_SIGNAL) != 0)
#define frame_total_len(flags0)  ((uint64_t)((flags0) & FRAME_LEN_MASK))

#ifndef PF_X
#define PF_X		0x1
#endif
#ifndef PF_W
#define PF_W		0x2
#endif
#ifndef PF_R
#define PF_R		0x4
#endif

struct bpf_insn {
    uint8_t	code;		/* opcode */
    uint8_t	dst_reg:4;	/* dest register */
    uint8_t	src_reg:4;	/* source register */
    int16_t	off;		/* signed offset */
    int32_t	imm;		/* signed immediate constant */
};

/*
For arithmetic and jump instructions the 8-bit 'code'
field is divided into three parts:
  +----------------+--------+--------------------+
  |   4 bits       |  1 bit |   3 bits           |
  | operation code | source | instruction class  |
  +----------------+--------+--------------------+
  (MSB)                                      (LSB)
 */

// classes
#define BPF_LD    0x00
#define BPF_LDX   0x01
#define BPF_ST    0x02
#define BPF_STX   0x03
#define BPF_ALU   0x04
#define BPF_JMP   0x05
#define BPF_JMP32 0x06
#define BPF_ALU64 0x07

// source operands
#define BPF_K     0x00 //use 32-bit immediate as source operand
#define BPF_X     0x08 //use 'src_reg' register as source operand

// op for BPF_ALU and BPF_ALU64
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60
#define BPF_RSH   0x70
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0
#define BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
#define BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
#define BPF_END   0xd0  /* eBPF only: endianness conversion */

//op for BPF_JMP and BPF_JMP32
#define BPF_JA    0x00  /* BPF_JMP only */
#define BPF_JEQ   0x10
#define BPF_JGT   0x20
#define BPF_JGE   0x30
#define BPF_JSET  0x40
#define BPF_JNE   0x50  /* eBPF only: jump != */
#define BPF_JSGT  0x60  /* eBPF only: signed '>' */
#define BPF_JSGE  0x70  /* eBPF only: signed '>=' */
#define BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
#define BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
#define BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
#define BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
#define BPF_JSLT  0xc0  /* eBPF only: signed '<' */
#define BPF_JSLE  0xd0  /* eBPF only: signed '<=' */

/*
For load and store instructions the 8-bit 'code' field is divided as:
  +--------+--------+-------------------+
  | 3 bits | 2 bits |   3 bits          |
  |  mode  |  size  | instruction class |
  +--------+--------+-------------------+
  (MSB)                             (LSB)
*/
// Size modifier for load and store
#define BPF_W   0x00    /* word */
#define BPF_H   0x08    /* half word */
#define BPF_B   0x10    /* byte */
#define BPF_DW  0x18    /* eBPF only, double word */

// Mode modifier for load and store
#define BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
#define BPF_ABS  0x20  /* legacy BPF packet access (absolute)*/
#define BPF_IND  0x40  /* legacy BPF packet access (indirect)*/
#define BPF_MEM  0x60  /* regular load and store operations */
#define BPF_MEMSX  0x80  /* sign-extension load operations */
#define BPF_ATOMIC 0xc0  /*atomic operations*/

// Atomic operation codes (encoded in imm field of BPF_ATOMIC instructions)
#define BPF_FETCH   0x01
#define BPF_XCHG    (0xe0 | BPF_FETCH)
#define BPF_CMPXCHG (0xf0 | BPF_FETCH)

class vm;
class JitCompilerBase;
class Pty;
template<typename T> class JitCompiler;

// handle_signals 通过本结构带回待投递信号：sig==0 表示无信号投递。
struct sig_info {
    int sig = 0;
    uint64_t handler = 0;   // guest handler 地址
    uint64_t sa_flags = 0;  // 投递信号的 sa_flags（含 SA_RESTART），供重启判定
};

inline constexpr int64_t SYSCALL_RESTART = -512;

class SyscallHandler{
protected:
    static auto& maps(vm* v);
    static auto& maps_ptr(vm* v);
    static auto& maps_mutex(vm* v);
    static auto& options(vm* v);
    static auto& signal_depth(vm* v);
    static auto& tp(vm* v);
public:
    virtual ~SyscallHandler() = default;
    virtual void init(const std::shared_ptr<vm>& v) = 0;
    virtual void fini(const std::shared_ptr<vm>& v) = 0;
    virtual int64_t (syscall)(vm* v, uint32_t call) = 0;
    // 宿主侧信号（物理终端 ^C / 终端挂断 / 外部 kill 给 bpfvm）转交 handler 路由。
    // handler 凭自己掌握的进程语义（session/ctty/前台组）决定投给谁：有控制终端走
    // 前台进程组，无 ctty 退化为投给该 vm 自身。默认实现 = 直接 queue 给该 vm。
    // 调用方（如 main.cpp 的信号 handler）不再关心"PTY 模式"等 host 侧接入细节。
    virtual void host_signal(vm* v, int sig) { (void)v; (void)sig; }
    virtual bool handle_signals(vm* v, sig_info* info) = 0;
    virtual int id() = 0;
};

// 当前加载的 ELF 程序镜像信息
//   entry：程序入口
//   load_base：主程序 PIE 加载基址。静态/ET_EXEC 为 0；
//   exe：host 视角绝对路径（= load_elf 的入参）。
struct vmImage {
    uint64_t entry = 0;
    uint64_t load_base = 0;
    std::string exe;
};

struct vmOptions {
    bool verbose = false;
    bool raw_stack = false;
    uint64_t insn_limit = 0;  // 0 = 无限制
    // 每个函数栈帧为编译器分配的局部变量预留的区大小（默认 16KiB，对齐
    // -mllvm -bpf-stack-size=16384）。可经 bpfvm -S 调整，用于与 guest 编译时
    // 的栈帧上限对齐。frame[0] 低 32 位存的总长度 = stack_limit + alloca_len。
    uint64_t stack_limit = 16 * 1024;
    std::vector<std::string> argv;
    std::map<std::string, std::string> envp;
    std::shared_ptr<SyscallHandler> sys;
    // host 接入器 + 信号路由器，始终非空。PTY 模式开真 pty（fd 0/1/2 接 slave）；
    // 非 PTY 模式退化为仅信号路由。pump 线程读 signalfd 后调 sys->host_signal。
    std::shared_ptr<Pty> pty = nullptr;
    // chroot 根目录（宿主绝对路径）。非空时 guest 文件系统被限制在此目录下
    // （--root）。空 = 不 chroot，维持现有行为。
    std::string root;
};

struct TlbEntry {
    uint64_t guest_base;
    uint64_t guest_end;
    unsigned char* host_base;
    uint32_t flags;
    bool cow;
};
constexpr size_t TLB_SIZE = 16;
static_assert((TLB_SIZE & (TLB_SIZE - 1)) == 0, "TLB_SIZE must be power of 2");

// 本仓库的 BPF-on-BPF 自举 target（cmake/bpfvm-bpf-toolchain.cmake）用 libc++ LLVM 19，
// 其 std::atomic<shared_ptr<T>> 至今未实现（__cpp_lib_atomic_shared_ptr 未定义、实例化即报
// "no member named 'atomic'"，llvm-project#99980）。insn.h 被两个 target 共享，故按
// __cpp_lib_atomic_shared_ptr 条件编译：有则用成员 atomic，否则回退到 std::atomic_load/store/
// compare_exchange_*_explicit 自由函数（libc++ 支持）。
//
// compare_exchange 失败会把 expected 更新为当前值（与 std::atomic 语义一致），便于 COW 重试循环。
template <class T>
class AtomicSharedPtr {
public:
    using value_type = std::shared_ptr<T>;

    // 默认构造持空 shared_ptr；可显式传入初值（如 make_shared<T>()）。
    AtomicSharedPtr() : AtomicSharedPtr(value_type{}) {}
    explicit AtomicSharedPtr(value_type init) {
#if defined(__cpp_lib_atomic_shared_ptr)
        atomic_.emplace(std::move(init));
#else
        ptr_ = std::move(init);
#endif
    }
    // std::atomic 不可拷贝，故本类也不可拷贝；需要拷贝处（如 SharedState copy ctor）
    // 用 AtomicSharedPtr(src.load()) 显式构造一个独立的新原子对象。
    AtomicSharedPtr(const AtomicSharedPtr&) = delete;
    AtomicSharedPtr& operator=(const AtomicSharedPtr&) = delete;

    value_type load() const {
#if defined(__cpp_lib_atomic_shared_ptr)
        return atomic_->load(std::memory_order_acquire);
#else
        return std::atomic_load_explicit(&ptr_, std::memory_order_acquire);
#endif
    }
    void store(value_type desired) {
#if defined(__cpp_lib_atomic_shared_ptr)
        atomic_->store(std::move(desired), std::memory_order_release);
#else
        std::atomic_store_explicit(&ptr_, std::move(desired), std::memory_order_release);
#endif
    }
    // COW CAS：成功返回 true 并替换为 desired；失败返回 false 并把 expected 更新为当前值。
    bool compare_exchange(value_type& expected, value_type desired) {
#if defined(__cpp_lib_atomic_shared_ptr)
        return atomic_->compare_exchange_weak(expected, std::move(desired),
                                              std::memory_order_acq_rel, std::memory_order_acquire);
#else
        return std::atomic_compare_exchange_weak_explicit(&ptr_, &expected, std::move(desired),
                                                          std::memory_order_acq_rel, std::memory_order_acquire);
#endif
    }
private:
#if defined(__cpp_lib_atomic_shared_ptr)
    // optional 绕开 std::atomic 不可拷贝构造的限制，让 copy/赋值被 delete 的同时
    // 仍能用 AtomicSharedPtr(value_type) 在 ctor body 内 emplace 构造成员。
    std::optional<std::atomic<value_type>> atomic_;
#else
    mutable value_type ptr_;
#endif
};

// 所有调试回调的不可变集合，整体原子替换（见 AtomicDebugHooks），让一次 GDB 会话配置的
// 回调原子生效，读端不会读到半新半旧的组合。
struct DebugHooks {
    // vm 派生（fork / CLONE_THREAD）通知：父 vm 在 do_clone 内同步调用。
    std::function<void(vm* parent, vm* child, bool is_thread)> create;
    // syscall entry/return 钩子：do_syscall 在执行真 syscall 的前/后同步调用。回调在 vm 线程
    // 内执行——回调阻塞即 vm 阻塞，返回即 vm 继续。命中 catch/exec 事件则回调自行
    // set_flags(VM_DEBUG_STOP)，调用方据此 debug_park（停止模型见 gdb_server.h 文件头）。
    std::function<void(vm* v, uint32_t call)> syscall_entry;
    std::function<void(vm* v, uint32_t call)> syscall_return;
    // 取指后执行前的停止点检查（软断点）。命中断点则 set_flags(VM_DEBUG_STOP)，调用方据此
    // debug_park。由 GdbServer 注册：闭包查 gdbserver 自维护的 per-vm 断点集。
    std::function<void(vm* v)> breakpoint;
};
class AtomicDebugHooks {
public:
    using value_type = std::shared_ptr<const DebugHooks>;
    AtomicDebugHooks() : ptr_(std::make_shared<const DebugHooks>()) {}
    value_type load() const { return ptr_.load(); }
    void store(value_type desired) { ptr_.store(std::move(desired)); }
private:
    AtomicSharedPtr<const DebugHooks> ptr_;
};

class vm: public std::enable_shared_from_this<vm> {
private:
    TlbEntry tlb[TLB_SIZE]{};
    vmOptions options;
    struct vmImage vmImage;
    uint64_t pc_;
    uint64_t reg[11];
    std::shared_ptr<std::list<memmap>> maps = std::make_shared<std::list<memmap>>();
    std::shared_ptr<std::mutex> maps_mutex = std::make_shared<std::mutex>();
    pthread_mutex_t wait_mutex;
    pthread_cond_t wait_cv;
    std::atomic<uint32_t> flags{0};
    size_t signal_depth = 0;
    uint64_t insn_count = 0;              // 已执行指令计数（JIT+解释器共用，单线程访问）
    uint64_t interp_insns = 0;            // 解释器执行的指令数
    uint64_t tp_ = 0;                     // thread pointer（BPF_SYS_SET_TLS 设置；单线程 TLS 模拟）

    std::unique_ptr<JitCompilerBase> jit;

    // ERESTARTSYS：可重启 syscall 被信号打断后，syscall() 返回 SYSCALL_RESTART，
    // do_syscall 在此记录该 syscall 指令地址。0 = 无待决重启。deliver_signal 投递
    // 信号时据此 + SA_RESTART 决定重启（PC 回该地址）或转 -EINTR，随后清零。
    uint64_t restart_syscall_pc_ = 0;

    // 调试回调集合（见 DebugHooks）。原子整体替换，fork/clone 时子继承父的快照。
    AtomicDebugHooks debug_hooks_;

    bool ld(const bpf_insn* cur);
    bool ldx(const bpf_insn* cur);
    bool st(const bpf_insn* cur);
    bool stx(const bpf_insn* cur);
    bool alu(const bpf_insn* cur);
    bool alu64(const bpf_insn* cur);
    bool jmp(const bpf_insn* cur);
    bool jmp32(const bpf_insn* cur);
    bool step();

    // 处理 syscall 形式的 BPF call 指令（src_reg=0）。
    bool do_syscall(uint32_t call) {
        if((flags.load(std::memory_order_acquire) & VM_DEBUG_ATTACHED) && debug_hooks_.load()) {
            debug_hooks_.load()->syscall_entry(this, call);  // 命中则内部 set VM_DEBUG_STOP
            if(flags.load(std::memory_order_acquire) & VM_DEBUG_STOP) debug_park();
        }
        int64_t ret = (options.sys->syscall)(this, call);
        if(ret == SYSCALL_RESTART) {
            // 重启：不写 r(0)（保留调用前的值，由重投递的 syscall 重新设置），记 pc 供重启。
            restart_syscall_pc_ = pc_;
            return true;
        }
        // 先把返回值写回 r(0)——含 exit/exit_group 的退出码（这俩 syscall 返回 code 并置
        // VM_EXITED）。必须在 VM_EXITED 检查之前，否则 exit 时 r(0) 残留调用前的值（多为 guest
        // 指针），run() 返回错误退出码。SYSCALL_RESTART 上面已提前 return，不会把 -512 写进 r(0)。
        r(0) = (uint64_t)ret;
        if(flags.load(std::memory_order_acquire) & (VM_EXITED | VM_KILLED)) {
            return false;
        }
        // return 钩子仅在 syscall 真正执行后报（重启/退出不报，符合 ptrace 语义）。
        if((flags.load(std::memory_order_acquire) & VM_DEBUG_ATTACHED) && debug_hooks_.load()) {
            debug_hooks_.load()->syscall_return(this, call);  // 命中 catch/exec 则 set VM_DEBUG_STOP
            if(flags.load(std::memory_order_acquire) & VM_DEBUG_STOP) debug_park();
        }
        return true;
    }

    // 虚拟浮点指令（src_reg=2）的解释器实现（编号见 include/bpf_fp.h 的 BPF_FP_* 宏）。
    bool do_softfp(uint32_t call);

    friend class SyscallHandler;
    template<typename T> friend class JitCompiler;
    void log_mem_violation(const char* type, uint64_t addr);
    bool safepoint();
    void debug_park();
    struct Token { explicit Token() = default; };
    uint64_t pop_frame();
public:
    static constexpr uint32_t VM_EXITED = 0x1;
    static constexpr uint32_t VM_STOPPED = 0x2;  //外部暂停，在safepoint等待
    static constexpr uint32_t VM_KILLED = 0x4;
    static constexpr uint32_t VM_SIGNAL_PENDING = 0x8;
    static constexpr uint32_t VM_BUDGET_EXCEEDED = 0x10;
    static constexpr uint32_t VM_BLOCKED = 0x20; //内部暂停，在wait_for等待
    static constexpr uint32_t VM_DEBUG_ATTACHED = 0x40;   //GDB 已 attach：JIT 跳过、解释器每步经 breakpoint 钩子判定
    static constexpr uint32_t VM_DEBUG_STOP = 0x80;       //GDB 请求停：钩子/事件回调/request_stop 设，debug_park 消费，continue 清；wait_for mask 含之以打断阻塞

    vm(Token);
    ~vm();

    static std::shared_ptr<vm> create();
    void* mmu(uint64_t addr, size_t size = 1);
    void* mmu_w(uint64_t addr, size_t size = 1);
    // Slow path: linear scan maps + fill TLB (no TLB lookup).  Called by JIT on miss.
    void* mmu_slow(uint64_t addr, size_t size);
    void* mmu_w_slow(uint64_t addr, size_t size);
    bool setup_stack(const std::vector<std::string>& argv,
                     const std::map<std::string, std::string>& envp,
                     const ElfLoadInfo& info);
    bool push_frame(uint64_t return_addr, bool is_signal = false);
    // 调用 handle_signals 决策并通过 push_frame 投递信号 handler（压信号帧、r(1)=sig、pc=handler）。
    bool deliver_signal();
    int64_t alloca(int64_t inc);
    // 通用阻塞原语：调用方先置 VM_BLOCKED（与其等待注册原子），再调用本函数。自身阻塞
    // 直至 wakeup(true) 清 VM_BLOCKED、或 VM_KILLED/VM_SIGNAL_PENDING 置位、或超时。
    // 返回 0（被唤醒）/ -EINTR（被信号/kill 打断）/ -ETIMEDOUT。
    // timeout 为相对时长，nullptr 表示无限等待（1s 兜底防 spurious）。
    int wait_for(const struct timespec* timeout);
    // 唤醒阻塞在 wait_for / safepoint 的vm。
    // clear_blocked=true：清 VM_BLOCKED，wait_for 返回 0（正常唤醒，如 futex_wake / IO 完成）。
    // clear_blocked=false：保留 VM_BLOCKED，仅 broadcast 让 waiter 重判信号 flag 而返回 -EINTR
    void wakeup(bool clear_blocked);
    ElfLoadInfo load_elf(const char* elf_file_path, const std::map<std::string, std::string>& envp);
    void addmem(memmap&& memmap);
    bool unmap(uint64_t addr);
    void flush_tlb();
    void clear_jit_cache();
    uint64_t& r(int n) {
        return reg[n];
    }
    uint64_t& pc() {
        return pc_;
    }
    std::shared_ptr<SyscallHandler> sys() {
        return options.sys;
    }
    struct vmImage& image() {
        return vmImage;
    }

    uint32_t get_flags() const { return flags.load(std::memory_order_acquire); }
    void clear_flags(uint32_t mask) { flags.fetch_and(~mask, std::memory_order_release); }
    void set_flags(uint32_t mask) { flags.fetch_or(mask, std::memory_order_release); }

    // vm 派生通知回调（GdbServer::start 注册、stop 清空）。整体替换 debug_hooks_。
    void set_debug_hooks(std::shared_ptr<const DebugHooks> hooks) {
        debug_hooks_.store(std::move(hooks));
    }
    // do_clone 在父 vm 线程上调用：hooks->create 非空则同步执行（父=this）。
    void notify_create(vm* child, bool is_thread) {
        auto hooks = debug_hooks_.load();
        if(!hooks->create) {
            // 仍把 hooks 继承给子（即使 create 回调为空，syscall 等其它钩子也要继承）
            child->debug_hooks_.store(hooks);
            return;
        }
        child->debug_hooks_.store(hooks);  // 子继承父的回调（多层 fork/线程树都能通知到本 server）
        hooks->create(this, child, is_thread);
    }

    uint64_t run();
    uint64_t run(const vmOptions* options, const ElfLoadInfo& info = ElfLoadInfo{});
    void dump_stats() const;
};

inline auto& SyscallHandler::maps(vm* v) { return *v->maps; }
inline auto& SyscallHandler::maps_ptr(vm* v) { return v->maps; }
inline auto& SyscallHandler::maps_mutex(vm* v) { return v->maps_mutex; }
inline auto& SyscallHandler::options(vm* v) { return v->options; }
inline auto& SyscallHandler::signal_depth(vm* v) { return v->signal_depth; }
inline auto& SyscallHandler::tp(vm* v) { return v->tp_; }

#endif //INSN_H
