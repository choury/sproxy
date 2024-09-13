#include "sockops.skel.h"
#include "common/common.h"

#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <arpa/inet.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if(level <= LIBBPF_WARN) {
        vslog(LOG_ERR, format, args);
    }else if(level <= LIBBPF_INFO) {
        vslog(LOG_INFO, format, args);
    }
    return 0;
}


static struct sockops* skel = NULL;
static struct bpf_link* progs[8] = {NULL};

void unload_bpf() {
    for(size_t i = 0; i < sizeof(progs)/sizeof(progs[1]); i ++) {
       struct bpf_link* prog = progs[i];
       if(prog == NULL) {
           break;
       }
       bpf_link__detach(prog);
       bpf_link__destroy(prog);
       progs[i] = NULL;
    }
    if(skel) {
        sockops__destroy(skel);
        skel = NULL;
    }
}

int load_bpf(const char* cgroup, const struct sockaddr_in* addr4, const struct sockaddr_in6* addr6) {
    int fd = open(cgroup, O_RDONLY);
    if (fd < 0) {
        LOGE("failed to open cgroup: %s\n", strerror(errno));
        return -1;
    }
    int root = open("/sys/fs/cgroup", O_RDONLY);
    if (root < 0) {
        LOGE("failed to open root cgroup: %s\n", strerror(errno));
        goto cleanup;
    }


    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    struct rlimit rlim_new = {
        .rlim_cur       = RLIM_INFINITY,
        .rlim_max       = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        LOGE("Failed to increase RLIMIT_MEMLOCK limit: %s\n", strerror(errno));
        goto cleanup;
    }

    /* Open load and verify BPF application */
    skel = sockops__open_and_load();
    if (!skel) {
        LOGE("Failed to open BPF skeleton\n");
        goto cleanup;
    }
    skel->bss->proxy_pid = getpid();
    skel->bss->proxy_ip4 = addr4->sin_addr.s_addr;
    skel->bss->proxy_port4 = ntohs(addr4->sin_port);
    skel->bss->proxy_ip6[0] = addr6->sin6_addr.s6_addr32[0];
    skel->bss->proxy_ip6[1] = addr6->sin6_addr.s6_addr32[1];
    skel->bss->proxy_ip6[2] = addr6->sin6_addr.s6_addr32[2];
    skel->bss->proxy_ip6[3] = addr6->sin6_addr.s6_addr32[3];
    skel->bss->proxy_port6 = ntohs(addr6->sin6_port);

    progs[0] = bpf_program__attach_cgroup(skel->progs.bpf_sockopt, root);
    if (progs[0] == NULL) {
        LOGE("failed to attach bpf_sockopt to root cgroup (%d)\n", root);
        goto cleanup;
    }

    progs[1] = bpf_program__attach_cgroup(skel->progs.bpf_egress, fd);
    if (progs[1] == NULL) {
        LOGE("failed to attach bpf_egress to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }


    progs[2] = bpf_program__attach_cgroup(skel->progs.bpf_connect4, fd);
    if (progs[2] == NULL) {
        LOGE("failed to attach bpf_connect4 to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }

    progs[3] = bpf_program__attach_cgroup(skel->progs.bpf_connect6, fd);
    if (progs[3] == NULL) {
        LOGE("failed to attach bpf_connect6 to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }

    progs[4] = bpf_program__attach_cgroup(skel->progs.bpf_sendmsg4, fd);
    if (progs[4] == NULL) {
        LOGE("failed to attach bpf_sendmsg4 to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }

    progs[5] = bpf_program__attach_cgroup(skel->progs.bpf_sendmsg6, fd);
    if (progs[5] == NULL) {
        LOGE("failed to attach bpf_sendmsg6 to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }

    progs[6] = bpf_program__attach_cgroup(skel->progs.bpf_sock_release, fd);
    if (progs[6] == NULL) {
        LOGE("failed to attach bpf_sock_release to cgroup %s (%d)\n", cgroup, fd);
        goto cleanup;
    }
    if(root >= 0) close(root);
    if(fd >= 0) close(fd);
    return 0;

cleanup:
    unload_bpf();
    if(root >= 0) close(root);
    if(fd >= 0) close(fd);
    return -1;
}
