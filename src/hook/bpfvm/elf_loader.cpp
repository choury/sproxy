//
// elf_loader.cpp — BPF ELF 加载与库搜索公共逻辑（ld_main 和 VM 共用）
//

#include "elf_loader.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <elf.h>   // Elf64_Ehdr / Elf64_Phdr（系统头，glibc/musl 都自带；BPF 固定 ELF64）

// ===== memmap =====

memmap memmap::static_map(void* addr, size_t size, uint64_t paddr, std::string path_) {
    memmap map;
    map.size = size;
    map.set_data((unsigned char*)addr, size, false);
    map.paddr = paddr;
    map.flags = PF_R;
    map.path = std::move(path_);
    return map;
}


// ===== 库搜索 =====
// 运行期 loader 的 chroot 根（由 main.cpp --root 经 set_loader_root 注入；默认空 = 宿主路径）。
// 非空时 find_library 会在 root 内补搜，使动态主程序的 PT_INTERP 在 rootfs 内可定位。
static std::string g_loader_root;

void set_loader_root(const std::string& root) {
    // realpath 规范化：与 PosixSyscall::init 里 ps->root 的来源保持一致（都经 realpath），
    // 否则 guest_view 的前缀剥除会因相对路径/符号链接不匹配而失效，泄漏宿主绝对路径。
    if (const char* rp = realpath(root.c_str(), nullptr)) {
        g_loader_root = rp;
        free((void*)rp);
    } else {
        g_loader_root = root;
    }
    if (!g_loader_root.empty() && g_loader_root.back() == '/') {
        g_loader_root.pop_back();
    }
}

// 把宿主路径（load_elf 实际打开的、拼了 root 前缀的路径）转回 guest 视角路径，用于诊断输出。
// chroot 模式下诊断信息会进入 guest 可见的 stderr，不能泄漏 root 的宿主绝对路径
// （如 /home/user/.../root/bin/ls）——剥掉 g_loader_root 前缀后只显示 guest 看到的 /bin/ls。
// 非 chroot 模式原样返回。非 root 前缀开头的路径（如宿主搜索到的 .so）也原样返回。
static std::string guest_view(const std::string& host_path) {
    if (g_loader_root.empty()) return host_path;
    if (host_path == g_loader_root) return "/";
    const std::string prefix = g_loader_root + "/";
    if (host_path.compare(0, prefix.size(), prefix) == 0) {
        return "/" + host_path.substr(prefix.size());
    }
    return host_path;
}

static std::vector<std::string> default_lib_search_dirs() {
    std::vector<std::string> dirs;
    // 不再读宿主 getenv("LD_LIBRARY_PATH")：库搜索路径由调用方经 envp 显式传入
    // （VM 运行时用 guest envp，ld_main 自己读 host getenv 后并入 opt.lib_dirs）。
    dirs.push_back("lib");
    dirs.push_back(".");
    // chroot 模式：在 rootfs 内补搜标准 lib 目录（优先于宿主，因 interp 在 rootfs 内）。
    if (!g_loader_root.empty()) {
        dirs.insert(dirs.begin(), g_loader_root + "/lib");
        dirs.insert(dirs.begin(), g_loader_root + "/lib64");
        dirs.insert(dirs.begin(), g_loader_root);
    }
    return dirs;
}

// 从 envp（key→value）解析 LD_LIBRARY_PATH，按 ':' 拆成目录列表。
// elf_loader 不再读宿主 getenv；VM 运行时把 guest 的 envp 传入，由本函数提取库搜索路径。
std::vector<std::string> lib_search_dirs_from_envp(const std::map<std::string, std::string>& envp) {
    std::vector<std::string> dirs;
    auto it = envp.find("LD_LIBRARY_PATH");
    if (it == envp.end()) return dirs;
    std::stringstream ss(it->second);
    std::string d;
    while (std::getline(ss, d, ':')) {
        if (!d.empty()) dirs.push_back(d);
    }
    return dirs;
}

std::string find_library(const std::vector<std::string>& extra_dirs, const std::string& name) {
    for (const auto& d : extra_dirs) {
        std::string p = d + "/" + name;
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    for (const auto& d : default_lib_search_dirs()) {
        std::string p = d + "/" + name;
        if (access(p.c_str(), R_OK) == 0) return p;
    }
    if (access(name.c_str(), R_OK) == 0) return name;
    return "";
}

// ===== ELF 加载 =====

namespace {

class Defer {
public:
    Defer(std::function<void()> f) : func(f) {}
    ~Defer() { func(); }
private:
    std::function<void()> func;
};

// 构造一个「加载失败」结果：entry=0 + err=<errno>。供 load_elf 各失败点统一使用，
// 让 do_execveat 能拿到精确 errno（ENOENT/EACCES/ENOEXEC...），替代历史上笼统的 ENOEXEC。
static ElfLoadInfo fail(int err) {
    ElfLoadInfo info;
    info.err = err;
    return info;
}

// 一个打开的 ELF 模块（主程序或 .so 依赖）。
struct ElfFile { std::string path; Elf64_Ehdr ehdr; int fd; };

// 待加载的 PT_LOAD 段（按文件索引 + 实际 vaddr）
struct Seg {
    size_t file_idx;
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t offset;
    uint64_t filesz;
    uint32_t flags;
};

// 读 + 校验 ELF64 header（64 字节）。BPF 固定 ELFCLASS64 + ELFDATA2LSB（小端 64 位），
// 故魔数检查并入此函数（等价于原 elf_begin + elf_kind + gelf_getehdr 三步合一）。
// 成功返回 true 并填 out；失败填具体原因到 err_reason（供调用方诊断输出）。
static bool read_ehdr(int fd, Elf64_Ehdr& out, const char*& err_reason) {
    ssize_t n = pread(fd, &out, sizeof(out), 0);
    if (n != sizeof(out)) { err_reason = "short read on ehdr"; return false; }
    if (std::memcmp(out.e_ident, ELFMAG, SELFMAG) != 0) { err_reason = "bad ELF magic"; return false; }
    if (out.e_ident[EI_CLASS] != ELFCLASS64) { err_reason = "not ELF64"; return false; }
    if (out.e_ident[EI_DATA] != ELFDATA2LSB) { err_reason = "not little-endian"; return false; }
    return true;
}

// 读第 i 个 program header（56 字节）。基于 ehdr 的 e_phoff/e_phentsize 定位。
static bool read_phdr(int fd, const Elf64_Ehdr& eh, int i, Elf64_Phdr& out) {
    off_t off = eh.e_phoff + (off_t)i * eh.e_phentsize;
    ssize_t n = pread(fd, &out, sizeof(out), off);
    return n == sizeof(out);
}

bool validate_ehdr(const Elf64_Ehdr& eh, const char* path) {
    if (eh.e_type == ET_REL) {
        std::cerr << "bpfvm: ET_REL not supported; link with bpfvm-ld first: " << guest_view(path) << std::endl;
        return false;
    }
    if (eh.e_type != ET_EXEC && eh.e_type != ET_DYN) {
        std::cerr << "Not an executable ELF file: " << guest_view(path) << " type: " << eh.e_type << std::endl;
        return false;
    }
    if (eh.e_machine != EM_BPF) {
        std::cerr << "Not a bpf ELF file: " << guest_view(path) << " machine: " << eh.e_machine << std::endl;
        return false;
    }
    return true;
}

// 扫描一个模块的所有 PT_LOAD 段，分配加载基址并填充 segs。
//   ET_DYN（PIE/.so）：先扫所有 PT_LOAD 算模块跨度，从 next_alloc 整块分配，
//                     保持模块内相对布局。
//   ET_EXEC：p_vaddr 是绝对地址，st_value 也是绝对地址，base=0
void layout_module(const ElfFile& ef, size_t fi, bool is_dyn,
                  uint64_t& next_alloc, uint64_t& base_out,
                  std::vector<Seg>& segs) {
    const Elf64_Ehdr& eh = ef.ehdr;

    if (is_dyn) {
        uint64_t min_v = UINT64_MAX, max_end = 0;
        for (size_t i = 0; i < eh.e_phnum; i++) {
            Elf64_Phdr ph;
            if (!read_phdr(ef.fd, eh, i, ph)) continue;
            if (ph.p_type != PT_LOAD) continue;
            if (ph.p_vaddr < min_v) min_v = ph.p_vaddr;
            if (ph.p_vaddr + ph.p_memsz > max_end) max_end = ph.p_vaddr + ph.p_memsz;
        }
        uint64_t mod_base = next_alloc - min_v;  // 实际地址 = mod_base + p_vaddr
        uint64_t mod_span = max_end - min_v;
        next_alloc = (next_alloc + mod_span + 0xFFF) & ~0xFFFULL;
        base_out = mod_base + min_v;  // 首个段实际 vaddr
        for (size_t i = 0; i < eh.e_phnum; i++) {
            Elf64_Phdr ph;
            if (!read_phdr(ef.fd, eh, i, ph)) continue;
            if (ph.p_type != PT_LOAD) continue;
            segs.push_back({fi, mod_base + ph.p_vaddr, ph.p_memsz, ph.p_offset, ph.p_filesz, ph.p_flags});
        }
    } else {
        // ET_EXEC：段 vaddr 已是绝对地址（bpfvm-ld 写死 guest_base_ 起），直接按 phdr 映射。
        // 首段覆盖 ELF header + phdr table 的扩展由 bpfvm-ld 在产物里完成（PT_PHDR 配套），
        // loader 不再需要特例处理。
        base_out = 0;
        for (size_t i = 0; i < eh.e_phnum; i++) {
            Elf64_Phdr ph;
            if (!read_phdr(ef.fd, eh, i, ph)) continue;
            if (ph.p_type != PT_LOAD) continue;
            segs.push_back({fi, ph.p_vaddr, ph.p_memsz, ph.p_offset, ph.p_filesz, ph.p_flags});
        }
    }
}

bool check_overlaps(const std::vector<Seg>& segs, const std::vector<ElfFile>& elves) {
    for (size_t i = 0; i < segs.size(); i++) {
        for (size_t j = i + 1; j < segs.size(); j++) {
            uint64_t a0 = segs[i].vaddr, a1 = a0 + segs[i].memsz;
            uint64_t b0 = segs[j].vaddr, b1 = b0 + segs[j].memsz;
            if (a0 < b1 && b0 < a1) {
                std::cerr << "[load_elf] overlapping PT_LOAD: "
                          << elves[segs[i].file_idx].path << " @0x" << std::hex << a0 << "-0x" << a1
                          << " vs " << elves[segs[j].file_idx].path << " @0x" << b0 << "-0x" << b1
                          << std::dec << std::endl;
                return false;
            }
        }
    }
    return true;
}

// mmap + pread 单个段。段权限由 seg.flags 决定，存入 memmap.flags（静态路径）；
// ldso 路径在调用方另行加 PF_W（guest ldso 重定位时要写 text 段 lddw imm）。
bool map_segment(const Seg& s, const ElfFile& ef, memmap& m_out) {
    // 按页对齐映射（与 Linux 内核 PT_LOAD 语义一致）：覆盖 [vaddr&-PAGE, (vaddr+memsz+PAGE-1)&-PAGE)。
    // 若只映射精确 memsz，则段尾的页内间隙（[vaddr+memsz, 页尾)）在 guest 地址空间里是未映射的；
    constexpr size_t PAGE = 0x1000;
    uint64_t page_start = s.vaddr & ~(PAGE - 1);
    uint64_t page_end = (s.vaddr + s.memsz + PAGE - 1) & ~(PAGE - 1);
    size_t map_size = page_end - page_start;
    size_t head_off = s.vaddr - page_start;  // 段在页内的起始偏移

    void* host = mmap(nullptr, map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (host == MAP_FAILED) {
        std::cerr << "[load_elf] mmap failed for " << guest_view(ef.path)
                  << " @0x" << std::hex << s.vaddr << std::dec
                  << ": " << strerror(errno) << std::endl;
        return false;
    }
    if (s.filesz > 0) {
        ssize_t n = pread(ef.fd, (char*)host + head_off, s.filesz, s.offset);
        if (n < 0 || (uint64_t)n != s.filesz) {
            std::cerr << "[load_elf] short/failed pread of " << guest_view(ef.path) << ": "
                      << n << "/" << s.filesz << std::endl;
            munmap(host, map_size);
            return false;
        }
    }
    m_out.paddr = page_start;
    m_out.size = map_size;
    m_out.flags = s.flags;
    m_out.set_data((unsigned char*)host, map_size, /*own=*/true);
    return true;
}

}  // namespace

// ldso 模式加载：主程序是动态可执行（ET_DYN + PT_INTERP），由 ld-bpf.so 在 VM 内部完成
// 依赖加载、重定位、TLS 建立、init_array 调用、控制转移。本函数只负责把主程序和 ldso 的
// PT_LOAD 段 mmap 进 guest 地址空间（不解析依赖、不重定位——这些都由 guest ldso 做），
// 返回 entry=ldso 的 _dlstart、phdr=主程序 phdr、ldso_base=ldso 加载基址。
// ElfFile/Seg/layout_module/map_segment 等辅助结构与静态路径共用。
ElfLoadInfo load_elf_ldso(ElfFile& main_ef, const char* interp_path,
                           std::function<void(memmap&&)>& add,
                           std::vector<std::pair<int, int>>& opened,
                           const std::map<std::string, std::string>& envp) {
    // 定位 ldso 文件：PT_INTERP 路径（如 /lib/ld-bpf.so）→ 在库搜索路径找。
    // 搜索路径由 guest envp 里的 LD_LIBRARY_PATH 决定（POSIX 语义）。
    std::string interp_name = interp_path;
    size_t slash = interp_name.find_last_of('/');
    if (slash != std::string::npos) interp_name = interp_name.substr(slash + 1);
    std::string ldso_path = find_library(lib_search_dirs_from_envp(envp), interp_name);
    if (ldso_path.empty()) {
        std::cerr << "[load_elf] ldso not found: " << interp_path
                  << " (searched LD_LIBRARY_PATH + default dirs for " << interp_name << ")\n";
        // interp（动态链接器）找不到：对 guest 而言是程序所需的解释器不存在 → ENOENT。
        return fail(ENOENT);
    }
    // open ldso + 读 ehdr（手写解析，等价原 elf_begin + gelf_getehdr）。
    int ldso_fd = open(ldso_path.c_str(), O_RDONLY);
    if (ldso_fd < 0) {
        std::cerr << "[load_elf] failed to open ldso: " << guest_view(ldso_path) << ": " << strerror(errno) << "\n";
        return fail(errno ? errno : ENOENT);
    }
    Elf64_Ehdr ldso_ehdr;
    const char* err_reason = nullptr;
    if (!read_ehdr(ldso_fd, ldso_ehdr, err_reason)) {
        std::cerr << "[load_elf] failed to read ldso ehdr (" << err_reason << "): "
                  << guest_view(ldso_path) << "\n";
        close(ldso_fd);
        return fail(ENOEXEC);
    }
    // opened 存 fd（由 load_elf 的 defer_close 统一关闭）；首元素 = 占位（main fd 由 load_elf 关）。
    opened.push_back({ldso_fd, ldso_fd});

    // 地址分配 + 段布局：主程序（elves[0]）+ ldso（elves[1]），都按 ET_DYN PIE 分配。
    //    不解析 DT_NEEDED、不收集依赖——那些由 guest ldso 在运行时自己 open/mmap。
    std::vector<ElfFile> elves = {{main_ef.path, main_ef.ehdr, main_ef.fd},
                                  {ldso_path, ldso_ehdr, ldso_fd}};
    uint64_t next_alloc = 0x40000000ULL;
    std::vector<uint64_t> load_base(elves.size(), 0);
    std::vector<Seg> segs;
    for (size_t fi = 0; fi < elves.size(); fi++) {
        layout_module(elves[fi], fi, elves[fi].ehdr.e_type == ET_DYN, next_alloc, load_base[fi], segs);
    }
    if (segs.empty()) {
        std::cerr << "[load_elf] no PT_LOAD segments (ldso mode)\n";
        return fail(ENOEXEC);
    }
    if (!check_overlaps(segs, elves)) return fail(ENOEXEC);

    // mmap 每段。所有段强制加 PF_W（guest ldso 重定位时要写 text/data 段的 lddw imm，
    //    VM 的 mmu_w 按 memmap.flags 检查写权限，text 段 p_flags 无 W 会被拦截）。
    //    重定位完成后由 ldso 的 RELRO/mprotect 逻辑收紧权限（标准 ldso 模型）。
    for (const auto& s : segs) {
        memmap m;
        if (!map_segment(s, elves[s.file_idx], m)) return fail(ENOEXEC);
        m.flags = s.flags | PF_W;
        m.path = guest_view(elves[s.file_idx].path);
        add(std::move(m));
    }


    // 入口 = ldso 的 e_entry（相对 ldso base）+ ldso_base。
    uint64_t ldso_base = load_base[1];
    uint64_t entry = ldso_base + ldso_ehdr.e_entry;  // VM 执行入口 = ldso 的 _dlstart
    // 主程序入口（auxv AT_ENTRY 用）：ldso 完成动态链接后 CRTJMP(aux[AT_ENTRY]) 跳到这里
    // 移交控制权。必须是主程序的 e_entry（运行时 = load_base[0] + e_entry），而非 ldso 的
    // _dlstart——否则 CRTJMP 跳回 _dlstart → _dlstart_c → __dls2/3 → CRTJMP 无限递归 → 栈溢出。
    uint64_t app_entry = load_base[0] + main_ef.ehdr.e_entry;
    // 主程序 phdr 运行时地址（auxv AT_PHDR 用）。
    uint64_t phdr_addr = 0;
    for (size_t i = 0; i < main_ef.ehdr.e_phnum && phdr_addr == 0; i++) {
        Elf64_Phdr ph;
        if (!read_phdr(main_ef.fd, main_ef.ehdr, i, ph)) break;
        if (ph.p_type == PT_PHDR) phdr_addr = load_base[0] + ph.p_vaddr;
    }

    return ElfLoadInfo{entry, phdr_addr, main_ef.ehdr.e_phentsize, main_ef.ehdr.e_phnum, ldso_base, app_entry, load_base[0]};
}

ElfLoadInfo load_elf(const char* path, std::function<void(memmap&&)> add,
                     const std::map<std::string, std::string>& envp) {
    // 加载 ET_EXEC（静态，固定地址）或 ET_DYN（PIE 主程序 / .so，运行时分配地址）。
    // 运行时处理 .rela.dyn（数据/lddw 重定位）和 .rela.plt（GOT 槽）。
    int main_fd = open(path, O_RDONLY);
    if (main_fd < 0) {
        std::cerr << "Failed to open: " << guest_view(path) << ": " << strerror(errno) << std::endl;
        // 文件不存在/无权限等：传真实 errno（ENOENT/EACCES...），让 execve 报准。
        return fail(errno);
    }
    Elf64_Ehdr ehdr;
    const char* err_reason = nullptr;
    if (!read_ehdr(main_fd, ehdr, err_reason)) {
        std::cerr << "Failed to open ELF file: " << guest_view(path)
                  << " (" << err_reason << ")" << std::endl;
        close(main_fd);
        return fail(ENOEXEC);
    }
    // opened：存待关闭的 fd，Defer 统一关闭。
    std::vector<std::pair<int, int>> opened = {{main_fd, main_fd}};
    Defer defer_close([&]() {
        for (auto& [_, fd] : opened) { if (fd >= 0) close(fd); }
    });

    if (!validate_ehdr(ehdr, path)) return fail(ENOEXEC);

    // 动态链接检测：主程序有 PT_INTERP → ldso 模式（VM 只 mmap 主程序+ldso，依赖加载/
    // 重定位/TLS/init_array 全由 guest ldso 在 VM 内完成）。无 PT_INTERP → 静态，走原路径。
    for (size_t i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr ph;
        if (!read_phdr(main_fd, ehdr, i, ph)) break;
        if (ph.p_type == PT_INTERP && ph.p_filesz > 0) {
            std::string interp(ph.p_filesz, '\0');
            ssize_t n = pread(main_fd, interp.data(), ph.p_filesz, ph.p_offset);
            if (n > 0) {
                interp.resize(n);
                if (!interp.empty() && interp.back() == '\0') interp.pop_back();
                ElfFile main_ef_obj{path, ehdr, main_fd};
                return load_elf_ldso(main_ef_obj, interp.c_str(), add, opened, envp);
            }
        }
    }

    // 静态路径（无 PT_INTERP）：bpfvm-ld -static 产物，自包含 ET_EXEC（固定地址），
    // 链接期已应用全部重定位，无 .dynamic/.rela.dyn/DT_NEEDED。loader 只需 mmap 段 +
    // 算 entry/phdr。动态链接（有 PT_INTERP）走上面的 load_elf_ldso，依赖加载/重定位/
    std::vector<ElfFile> elves;
    elves.push_back({path, ehdr, main_fd});

    // 地址分配 + 段布局
    uint64_t next_alloc = 0x40000000ULL;
    std::vector<uint64_t> load_base(elves.size(), 0);
    std::vector<Seg> segs;
    for (size_t fi = 0; fi < elves.size(); fi++) {
        layout_module(elves[fi], fi, elves[fi].ehdr.e_type == ET_DYN, next_alloc, load_base[fi], segs);
    }
    if (segs.empty()) {
        std::cerr << "[load_elf] no PT_LOAD segments in " << guest_view(path) << std::endl;
        return fail(ENOEXEC);
    }
    if (!check_overlaps(segs, elves)) return fail(ENOEXEC);

    for (const auto& s : segs) {
        memmap m;
        if (!map_segment(s, elves[s.file_idx], m)) return fail(ENOEXEC);
        m.path = guest_view(elves[s.file_idx].path);
        add(std::move(m));
    }

    // 入口地址：ET_DYN（PIE）→ 主程序加载基址 + e_entry；ET_EXEC → e_entry（绝对）
    const uint64_t entry = (ehdr.e_type == ET_DYN) ? (load_base[0] + ehdr.e_entry) : ehdr.e_entry;

    // program header table 的运行时地址（供 auxv AT_PHDR，musl __init_tls 用）：
    // 直接读 PT_PHDR 段。bpfvm-ld 对所有可执行文件（ET_EXEC + PIE）都生成 PT_PHDR，
    // 其 p_vaddr 是 phdr 表的绝对/相对地址，loader 加上加载基址即得运行时地址。
    // ET_EXEC：p_vaddr 已是绝对地址，load_base[0]=0；PIE：p_vaddr 是模块内偏移，加 load_base[0]。
    uint64_t phdr_addr = 0;
    for (size_t i = 0; i < ehdr.e_phnum && phdr_addr == 0; i++) {
        Elf64_Phdr ph;
        if (!read_phdr(main_fd, ehdr, i, ph)) break;
        if (ph.p_type == PT_PHDR) {
            phdr_addr = load_base[0] + ph.p_vaddr;
        }
    }

    return ElfLoadInfo{entry, phdr_addr, ehdr.e_phentsize, ehdr.e_phnum, 0, entry, load_base[0]};
}
