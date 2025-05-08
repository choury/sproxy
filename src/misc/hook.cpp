#include "hook.h"

#include <fcntl.h>
#include <unistd.h>
#include <cxxabi.h>
#ifdef HAVE_ELF
#include <gelf.h>
#endif

#include <regex>

HookManager hookManager;

#if __linux__
#include <linux/limits.h>
uint64_t parse_maps() {
    char elf_path[PATH_MAX];
    if(readlink("/proc/self/exe", elf_path, PATH_MAX) < 0) {
        LOGE("readlink of exe: %s\n", strerror(errno));
        return 0;
    }
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
            sscanf(line, "%lx", &base_address);
            break;
        }
    }
    fclose(maps);
    return base_address;
}
#endif

HookManager::HookManager() {
#ifdef HAVE_ELF
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
                // 获取符号名
                char* name = abi::__cxa_demangle((char *)str_data->d_buf + sym.st_name, nullptr, nullptr, nullptr);
                if(name == nullptr || startwith(name, "guard variable") || !endwith(name, "__hook_registed")) {
                    free(name);
                    continue;  // 跳过不相关变量
                }
                std::string_view unmangled(name);
                auto pos = unmangled.rfind("::");
                auto lpos = unmangled.rfind("__hook_registed");
                hookers.emplace((void*)(base_addr + sym.st_value),
                                std::string(unmangled.data(), pos) + ":" + std::string(name + pos + 4, lpos - pos - 4));
                free(name);
            }
        }
    }
    elf_end(elf);
    close(fd);
#endif
}
