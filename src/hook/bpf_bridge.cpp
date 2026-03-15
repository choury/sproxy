#include "bpf_bridge.h"
#include "common/common.h"
#include "include/bpf_call.h"

#include <cstring>
#include <sys/mman.h>

class BpfSyscallHandler : public SyscallHandler {
    BpfCallArgs* bpf_args;
    std::string elf_path;
public:
    BpfSyscallHandler(BpfCallArgs* args, const std::string& path) : bpf_args(args), elf_path(path) {}

    void init(const std::shared_ptr<vm>&) override {}
    void fini(const std::shared_ptr<vm>&) override {}
    int id() override { return 1; }
    void queue_signal(vm*, int) override {}
    bool handle_signals(vm*) override { return true; }

    bool syscall(vm* v, uint32_t sys_id) override {
        switch (sys_id) {
        case BPF_CALL_KV_SET: {
            // r1 = key_ptr, r2 = key_len, r3 = val_ptr, r4 = val_len, r5 = type
            uint64_t key_addr = v->r(1);
            uint64_t key_len = v->r(2);
            uint64_t val_addr = v->r(3);
            uint64_t val_len = v->r(4);
            uint64_t type = v->r(5);

            void* key_mem = v->mmu(key_addr, key_len);
            if (!key_mem) {
                v->r(0) = (uint64_t)-EFAULT;
                return true;
            }
            std::string key((const char*)key_mem, key_len);

            BpfKV kv;
            switch (type) {
            case 1: { // INT64
                if (val_len < sizeof(int64_t)) {
                    v->r(0) = (uint64_t)-EINVAL;
                    return true;
                }
                void* vp = v->mmu(val_addr, sizeof(int64_t));
                if (!vp) {
                    v->r(0) = (uint64_t)-EFAULT;
                    return true;
                }
                kv = BpfKV::make_int(*(int64_t*)vp);
                break;
            }
            case 2: { // UINT64
                if (val_len < sizeof(uint64_t)) {
                    v->r(0) = (uint64_t)-EINVAL;
                    return true;
                }
                void* vp = v->mmu(val_addr, sizeof(uint64_t));
                if (!vp) {
                    v->r(0) = (uint64_t)-EFAULT;
                    return true;
                }
                kv = BpfKV::make_uint(*(uint64_t*)vp);
                break;
            }
            case 3: { // STRING
                void* vp = v->mmu(val_addr, val_len);
                if (!vp) {
                    v->r(0) = (uint64_t)-EFAULT;
                    return true;
                }
                kv = BpfKV::make_string(std::string((const char*)vp, val_len));
                break;
            }
            case 4: { // BYTES
                void* vp = v->mmu(val_addr, val_len);
                if (!vp) {
                    v->r(0) = (uint64_t)-EFAULT;
                    return true;
                }
                kv = BpfKV::make_bytes(vp, val_len);
                break;
            }
            default:
                v->r(0) = (uint64_t)-EINVAL;
                return true;
            }

            bpf_args->kv_set(key, kv);
            v->r(0) = 0;
            return true;
        }

        case BPF_CALL_LOG: {
            // r1 = level, r2 = msg_ptr, r3 = msg_len
            int level = (int)(int32_t)v->r(1);
            uint64_t msg_addr = v->r(2);
            uint64_t msg_len = v->r(3);

            void* msg_mem = v->mmu(msg_addr, msg_len);
            if (!msg_mem) {
                v->r(0) = (uint64_t)-EFAULT;
                return true;
            }
            std::string msg((const char*)msg_mem, msg_len);
            slog(level, "bpf[%s]: %s\n", elf_path.c_str(), msg.c_str());
            v->r(0) = 0;
            return true;
        }

        default:
            v->r(0) = (uint64_t)-ENOSYS;
            return true;
        }
    }
};

// ============ BpfCallback implementation ============
BpfCallback::BpfCallback(const std::string& elf_path, std::string& msg)
    : elf_path(elf_path) {
    msg.clear();

    v = vm::create();
    entry = v->load_elf(elf_path.c_str());
    if (entry == 0) {
        msg = "Failed to load BPF ELF: " + elf_path;
    }
}

void BpfCallback::OnCall(void* args) {
    if (entry == 0) return;
    auto* bpf_args = static_cast<BpfCallArgs*>(args);

    // Install syscall handler
    vmOptions options;
    options.sys = std::make_shared<BpfSyscallHandler>(bpf_args, elf_path);
    options.entry = entry;
    options.raw_stack = true; // Use R1/R2 instead of argv/envp string setup

    // Map protobuf data into VM memory
    uint64_t pb_addr = 0x20000000ULL;
    size_t pb_size = bpf_args->pb_data.size();
    v->r(1) = pb_addr;
    v->r(2) = pb_size;
    v->addmem(memmap::static_map(bpf_args->pb_data.data(), pb_size, pb_addr));
    // Run BPF program: main(pb_ptr, pb_len)
    v->run(&options);
    v->unmap(pb_addr);
}
