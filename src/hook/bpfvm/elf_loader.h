//
// elf_loader.h — BPF ELF 加载与库搜索公共逻辑
//
// ld_main（构建期 -l 解析）和 VM（运行期加载 ELF）共用。
//
// 搜索顺序：命令行 -L 目录 -> LD_LIBRARY_PATH -> 内置默认（lib, .；chroot --root 模式额外补搜 root/lib64, root/lib, root）
//
// load_elf 通过 std::function 回调把映射好的 memmap 交给调用方，
//

#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <sys/mman.h>
#include <vector>

// unique_ptr deleter：own=true 时 munmap；也用作 CoW 共享页的 deleter。
// 单一 `owned` flag 控制是否 munmap，两种角色用同一路径。
struct DataDeleter {
    size_t size = 0;
    bool owned = false;
    DataDeleter() = default;
    DataDeleter(size_t sz, bool own) : size(sz), owned(own) {}
    void operator()(unsigned char* p) {
        if (owned && p && p != (unsigned char*)MAP_FAILED)
            munmap(p, size);
    }
};

// guest 内存映射描述：paddr 是 guest 虚拟地址，data 指向 host mmap 区。
struct memmap {
    std::unique_ptr<unsigned char, DataDeleter> data{nullptr, DataDeleter{0, false}};
    size_t size = 0;
    uint64_t paddr = 0;
    uint32_t flags = 0;
    // non-null: CoW page shared across VMs; DataDeleter owns the actual munmap call.
    std::shared_ptr<unsigned char> cow_data;
    std::string path;
    memmap() = default;
    memmap(memmap&&) = default;
    memmap& operator=(memmap&&) = default;
    void set_data(unsigned char* p, size_t sz, bool own = true) {
        data = std::unique_ptr<unsigned char, DataDeleter>(p, DataDeleter{sz, own});
    }
    static memmap static_map(void* addr, size_t size, uint64_t paddr, std::string path_ = "");
};

// 在 extra_dirs + 默认路径里找 name（dir + "/" + name）。
// name 若是绝对路径或当前目录可直接访问的文件，原样返回。找不到返回空串。
std::string find_library(const std::vector<std::string>& extra_dirs, const std::string& name);

// 从 envp（key->value）里解析 LD_LIBRARY_PATH，按 ':' 拆成目录列表。
// elf_loader 不再读宿主 getenv；调用方（VM 运行时）传入 guest 的 envp（-e 注入或
// execve 的 envp），由本函数取出影响库搜索的变量。当前仅 LD_LIBRARY_PATH，便于
// 将来扩展（LD_PRELOAD 等）。
std::vector<std::string> lib_search_dirs_from_envp(const std::map<std::string, std::string>& envp);

// 设定运行期 loader 的 chroot 根目录（--root）。非空时 find_library 的默认搜索路径
// 与 load_elf_ldso 的 ldso 查找会在 root 内（root/lib、root/lib64 ...）补搜，使动态主程序
// 的 PT_INTERP（/lib/ld-bpf.so）在 rootfs 内可被定位。仅 bpfvm 运行时调用；bpfvm-ld 不调。
void set_loader_root(const std::string& root);

// 把宿主路径转回 guest 视角路径（剥掉 --root 前缀），用于诊断输出：chroot 模式下诊断
// 信息会进入 guest 可见 stderr，不能泄漏 root 的宿主绝对路径（如 /home/.../root/bin/ls）。
// 非 chroot 模式或非 root 前缀开头的路径（如宿主搜索到的 .so）原样返回。
std::string guest_view(const std::string& host_path);

// 主程序加载结果：除入口地址外，还带 auxv 启动所需的信息（musl/glibc 的
// __init_tls 靠 AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY 定位 program headers 与 TLS）。
// entry 为 0 表示加载失败；此时 err 给出失败原因（正 errno 值，如 ENOENT/EACCES/ENOEXEC），
// 供 do_execveat 等调用方映射为精确的 guest errno（替代历史上笼统的 ENOEXEC）。
// err 为 0 表示未设置（成功，或极早期失败回退到 ENOEXEC）。phdr 为 0 表示主程序无 PT_PHDR。
struct ElfLoadInfo {
    uint64_t entry = 0;
    uint64_t phdr = 0;     // program header table 的运行时 guest 虚拟地址
    uint64_t phent = 0;    // 单个 program header 字节数（通常 56）
    uint64_t phnum = 0;    // program header 个数
    uint64_t ldso_base = 0;  // 动态链接器（ld-bpf.so）加载基址；静态链接为 0。
                             // ldso 模式下 setup_stack 据此填 auxv AT_BASE（ldso 自举用：
                             // _dlstart 从 AT_BASE 读 Ehdr 扫 phdr 定位 .dynamic）。
    uint64_t app_entry = 0;  // 主程序入口运行时地址（auxv AT_ENTRY 用）。静态/普通动态模式
                             // 下 == entry（主程序自带 _start）；ldso 模式下 entry 是 ldso 的
                             // _dlstart（VM 从那里开始执行动态链接流程），而 AT_ENTRY 必须是
                             // 主程序入口——ldso 的 CRTJMP(aux[AT_ENTRY]) 跳到它移交控制权。
                             // 两者不同；0 表示回退用 entry（保持旧行为）。
    uint64_t app_load_base = 0;  // 主程序 PIE 加载基址（load_base[0]）。静态/ET_EXEC 为 0；
                                 // PIE（ET_DYN）下 = 运行时基址偏移，文件内地址 + 此值 = 运行时
                                 // 地址。GDB server 的 qOffsets 用它让 GDB 把符号/DWARF 文件内
                                 // 地址重定位到运行时地址（否则 PIE 断点命中不了）。
    int err = 0;           // 加载失败 errno（ENOENT/EACCES/ENOEXEC...）；成功时为 0。
};

// 加载 ELF：有 PT_INTERP 走 ldso 模式（只 mmap 主程序+ldso，依赖加载/重定位由 guest
// ldso 完成）；否则静态路径（mmap 段，链接期已重定位）。为每个 PT_LOAD 段构造 memmap
// 并通过 add 回调交给调用方（如 vm::addmem）。返回加载信息（entry 为 0 表失败）。
// main_fd 为已打开的宿主 fd，借用语义——本函数不关闭它，生命周期归调用方（可安全传
// VM fd 表内仍在使用的 fd，无须 dup）。加载过程中自行打开的 fd（ldso 等）仍由本函数
// 关闭。path 不会被打开，仅作诊断输出与 memmap/ElfFile 的路径记录（guest 视角）——
// 支持路径不可达但 fd 存活的场景（已删文件、经 /proc/self/fd/N 重开的 fd 等）。
ElfLoadInfo load_elf(int main_fd, const char* path, std::function<void(memmap&&)> add,
                     const std::map<std::string, std::string>& envp);

#endif // ELF_LOADER_H
