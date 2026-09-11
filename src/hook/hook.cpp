#include "hook.h"

#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <cxxabi.h>
#include <inttypes.h>
#if defined(__linux__) && defined(HAVE_LIBELF)
#include <gelf.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif


HookManager hookManager;

#if __linux__
#include <linux/limits.h>
uint64_t parse_maps() {
    char elf_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", elf_path, PATH_MAX - 1);
    if(len < 0) {
        LOGE("readlink of exe: %s\n", strerror(errno));
        return 0;
    }
    elf_path[len] = '\0';
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        LOGE("fopen /proc/self/maps: %s\n", strerror(errno));
        return 0;
    }

    uint64_t base_address = 0;
    char line[256];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, elf_path)) {
            // Parse the base address (start of the memory mapping)
            sscanf(line, "%" SCNx64, &base_address);
            break;
        }
    }
    fclose(maps);
    return base_address;
}
#endif

HookManager::HookManager() {
#if defined(__linux__) && defined(HAVE_LIBELF)
    // 初始化ELF库
    if (elf_version(EV_CURRENT) == EV_NONE) {
        LOGE("elf_version failed: %s\n", elf_errmsg(-1));
        return;
    }
    uint64_t base_addr = parse_maps();
    if(base_addr == 0) {
        return;
    }


    // 打开自身的可执行文件
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        LOGE("open /proc/self/exe failed: %s\n", strerror(errno));
        return;
    }

    Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
    if (!elf) {
        LOGE("elf_begin failed: %s\n", elf_errmsg(-1));
        close(fd);
        return;
    }

    // 查找符号表节
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            continue;
        }

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            // 获取符号表数据
            Elf_Data *data = elf_getdata(scn, NULL);
            if (!data) {
                continue;
            }

            // 获取字符串表
            Elf_Scn *str_scn = elf_getscn(elf, shdr.sh_link);
            Elf_Data *str_data = elf_getdata(str_scn, NULL);

            // 遍历符号
            int count = shdr.sh_size / shdr.sh_entsize;
            for (int i = 0; i < count; i++) {
                GElf_Sym sym;
                if (gelf_getsym(data, i, &sym) != &sym) {
                    continue;
                }

                if (sym.st_name == 0) {
                    continue;  // 跳过没有名称的符号
                }
                AddHookSymbol((void*)(base_addr + sym.st_value),
                              (const char*)str_data->d_buf + sym.st_name);
            }
        }
    }
    elf_end(elf);
    close(fd);
#elif defined(__APPLE__)
    const mach_header_64* header =
        reinterpret_cast<const mach_header_64*>(_dyld_get_image_header(0));
    if (header == nullptr || header->magic != MH_MAGIC_64) {
        LOGE("failed to get the main Mach-O image\n");
        return;
    }

    intptr_t slide = _dyld_get_image_vmaddr_slide(0);
    const load_command* command =
        reinterpret_cast<const load_command*>(header + 1);
    const symtab_command* symtab = nullptr;
    const segment_command_64* linkedit = nullptr;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if (command->cmd == LC_SYMTAB) {
            symtab = reinterpret_cast<const symtab_command*>(command);
        } else if (command->cmd == LC_SEGMENT_64 &&
                   strcmp(reinterpret_cast<const segment_command_64*>(command)->segname,
                          SEG_LINKEDIT) == 0) {
            linkedit = reinterpret_cast<const segment_command_64*>(command);
        }
        command = reinterpret_cast<const load_command*>(
            reinterpret_cast<const char*>(command) + command->cmdsize);
    }
    if (symtab == nullptr || linkedit == nullptr) {
        LOGE("main Mach-O image has no symbol table\n");
        return;
    }

    uintptr_t linkedit_base = static_cast<uintptr_t>(slide) +
                              linkedit->vmaddr - linkedit->fileoff;
    const auto* symbols = reinterpret_cast<const nlist_64*>(
        linkedit_base + symtab->symoff);
    const char* strings = reinterpret_cast<const char*>(
        linkedit_base + symtab->stroff);
    for (uint32_t i = 0; i < symtab->nsyms; ++i) {
        const nlist_64& sym = symbols[i];
        if (sym.n_un.n_strx >= symtab->strsize || sym.n_value == 0) {
            continue;
        }
        AddHookSymbol(reinterpret_cast<void*>(static_cast<uintptr_t>(slide) + sym.n_value),
                      strings + sym.n_un.n_strx);
    }
#endif
}

void HookManager::AddHookSymbol(const void* addr, const char* mangled) {
    char* name = abi::__cxa_demangle(mangled, nullptr, nullptr, nullptr);
    if(name == nullptr || startwith(name, "guard variable") ||
       !endwith(name, "__hook_registed")) {
        free(name);
        return;
    }
    std::string_view unmangled(name);
    auto pos = unmangled.rfind("::");
    auto lpos = unmangled.rfind("__hook_registed");
    if(pos != std::string_view::npos && lpos != std::string_view::npos) {
        // 变量名形如 __<行号>__hook_registed,跳过 "::" 和前导 "__" 提取行号
        hookers.emplace(addr, std::string(unmangled.data(), pos) + ":" +
                                  std::string(name + pos + 4, lpos - pos - 4));
    }
    free(name);
}

// Normalize a parameter name string for BPF path access.
// e.g. "  & obj " -> "obj", "** ptr" -> "ptr", "obj->field" -> "obj.field"
static std::string trim_param(std::string s) {
    auto not_strip = [](char c) { return c != ' ' && c != '\t' && c != '&' && c != '*'; };
    // trim right whitespace
    auto end = std::find_if(s.rbegin(), s.rend(), [](char c) { return c != ' ' && c != '\t'; }).base();
    s.erase(end, s.end());
    // strip leading whitespace, &, *
    auto start = std::find_if(s.begin(), s.end(), not_strip);
    s.erase(s.begin(), start);
    if (s.empty()) return {};
    // replace "->" with "."
    for (size_t pos = 0; (pos = s.find("->", pos)) != std::string::npos; pos += 1)
        s.replace(pos, 2, ".");
    return s;
}

bool HookManager::AddHooker(bool* hooker, std::string func, const char* line, std::vector<std::string> names) {
    hookers[hooker] = func + ":" + line;

    for (auto& name : names) {
        name = trim_param(std::move(name));
    }
    param_names_map[hooker] = std::move(names);

    return *hooker = true;
}
