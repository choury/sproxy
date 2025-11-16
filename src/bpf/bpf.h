#ifndef BPF_H__
#define BPF_H__

#ifdef __cplusplus
extern "C" {
#endif

int load_bpf(const char* cgroup, const struct sockaddr_in* addr4, const struct sockaddr_in6* addr6, uint32_t fwmark);
void unload_bpf();

#ifdef __cplusplus
}
#endif
#endif
