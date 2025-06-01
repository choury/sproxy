#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


#define SO_ORIGINAL_DST     80

#define AF_INET   2
#define AF_INET6  10

#define INADDR_LOOPBACK (0x7f000001)

struct sock_addr {
    __u8  family;
    __u8  pad1;   // this padding required for 64bit alignment
    __u16 pad2;   // else ebpf kernel verifier rejects loading of the program
    __u32 protocol;
    union{
        __u32 sip4;
        __u32 sip6[4];
        __u8  sip_raw[16];
    };
    union{
        __u32 dip4;
        __u32 dip6[4];
        __u8  dip_raw[16];
    };
    __u32 sport;
    __u32 dport;
    pid_t pid;
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
        __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)        __builtin_bswap16(x)
#define bpf_htons(x)        __builtin_bswap16(x)

#define bpf_ntohl(x)        __builtin_bswap32(x)
#define bpf_htonl(x)        __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
        __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)        (x)
#define bpf_htons(x)        (x)

#define bpf_ntohl(x)        (x)
#define bpf_htonl(x)        (x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif


char LICENSE[] SEC("license") = "GPL";

volatile pid_t proxy_pid;
volatile __u32 proxy_ip4;    //网络字节序
volatile __u16 proxy_port4;  //本地字节序
volatile __u32 proxy_ip6[4]; //网络字节序
volatile __u16 proxy_port6;  //本地字节序

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
	__type(key, __u64);
	__type(value, struct sock_addr);
}sock_map SEC(".maps");

struct sock_key {
	__u8  family;
	__u8  pad1;
	__u16 sport;
	__u32 protocol;

}__attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
	__type(key, struct sock_key);
	__type(value, __u64);
}cookie_map SEC(".maps");


__always_inline int redirect4(struct bpf_sock_addr* ctx) {
    if (proxy_port4 == 0) return 1;
    if ((bpf_get_current_pid_tgid() >> 32) == proxy_pid) return 1;
    if (ctx->user_family != AF_INET) return 1;
    if (ctx->user_ip4 == bpf_htonl(INADDR_LOOPBACK)) return 1;

    struct sock_addr sock;
    __builtin_memset(&sock, 0, sizeof(sock));
    bpf_get_current_comm(sock.comm, sizeof(sock.comm));
    sock.pid = bpf_get_current_pid_tgid() >> 32;
    sock.family = ctx->user_family;
    sock.protocol = ctx->protocol;
    sock.dip4 = ctx->user_ip4;
    sock.dport = bpf_ntohl(ctx->user_port) >> 16;


    __u64 cookie = bpf_get_socket_cookie(ctx);
    bpf_map_update_elem(&sock_map, &cookie, &sock, 0);
    bpf_printk("redirect4 %d: %d -> %d", ctx->protocol, cookie, bpf_ntohl(ctx->user_port) >> 16);

    ctx->user_ip4 = proxy_ip4;
    ctx->user_port = bpf_htonl(proxy_port4 << 16);
    return 1;
}

SEC("cgroup/connect4")
int bpf_connect4(struct bpf_sock_addr *ctx) {
    return redirect4(ctx);
}

SEC("cgroup/sendmsg4")
int bpf_sendmsg4(struct bpf_sock_addr *ctx) {
    return redirect4(ctx);
}

__always_inline int redirect6(struct bpf_sock_addr* ctx) {
    if (proxy_port6 == 0) return 1;
    if ((bpf_get_current_pid_tgid() >> 32) == proxy_pid) return 1;
    if (ctx->user_family != AF_INET6) return 1;
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 && ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) return 1;

    struct sock_addr sock;
    __builtin_memset(&sock, 0, sizeof(sock));
    bpf_get_current_comm(sock.comm, sizeof(sock.comm));
    sock.pid = bpf_get_current_pid_tgid() >> 32;
    sock.family = ctx->user_family;
    sock.protocol = ctx->protocol;
    sock.dip6[0] = ctx->user_ip6[0];
    sock.dip6[1] = ctx->user_ip6[1];
    sock.dip6[2] = ctx->user_ip6[2];
    sock.dip6[3] = ctx->user_ip6[3];
    sock.dport = bpf_ntohl(ctx->user_port) >> 16;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    bpf_map_update_elem(&sock_map, &cookie, &sock, 0);
    bpf_printk("redirect6 %d: %d -> %d", ctx->protocol, cookie, bpf_ntohl(ctx->user_port) >> 16);

    ctx->user_ip6[0] = proxy_ip6[0];
    ctx->user_ip6[1] = proxy_ip6[1];
    ctx->user_ip6[2] = proxy_ip6[2];
    ctx->user_ip6[3] = proxy_ip6[3];
    ctx->user_port = bpf_htonl(proxy_port6 << 16);
    return 1;
}

SEC("cgroup/connect6")
int bpf_connect6(struct bpf_sock_addr *ctx) {
    return redirect6(ctx);
}


SEC("cgroup/sendmsg6")
int bpf_sendmsg6(struct bpf_sock_addr *ctx) {
    return redirect6(ctx);
}

SEC("cgroup_skb/egress")
int bpf_egress(struct __sk_buff *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_addr *sock = bpf_map_lookup_elem(&sock_map, &cookie);
    if (!sock) {
        return 1;
    }
    if (sock->family == ctx->family && sock->sport == ctx->local_port) return 1;
    if (ctx->family == AF_INET) {
        sock->sip4 = bpf_htonl(ctx->local_ip4);
        sock->sport = ctx->local_port;

        struct sock_key key = {
            .family = sock->family,
            .protocol = sock->protocol,
            .sport = sock->sport,
            .pad1   = 0,
        };

        bpf_map_update_elem(&cookie_map, &key, &cookie, 0);
        bpf_printk("ipv4_egress %d  %d, %d, %d", cookie, key.family, key.protocol, key.sport);
    }else if(ctx->family == AF_INET6) {
        sock->sip6[0] = ctx->local_ip6[0];
        sock->sip6[1] = ctx->local_ip6[1];
        sock->sip6[2] = ctx->local_ip6[2];
        sock->sip6[3] = ctx->local_ip6[3];
        sock->sport = ctx->local_port;

        struct sock_key key = {
            .family = sock->family,
            .protocol = sock->protocol,
            .sport = sock->sport,
            .pad1   = 0,
        };
        bpf_map_update_elem(&cookie_map, &key, &cookie, 0);
        bpf_printk("ipv6_egress %d  %d, %d, %d", cookie, key.family, key.protocol, key.sport);
    }
    return 1;
}

__always_inline int getpeer4(struct bpf_sock_addr* ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) == proxy_pid) return 1;
    if (bpf_ntohl(ctx->user_port)>>16 != proxy_port4) return 1;
    if (ctx->user_family != AF_INET) return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_addr *sock = bpf_map_lookup_elem(&sock_map, &cookie);
    if (!sock) {
        return 1;
    }
    ctx->user_ip4 =  sock->dip4;
    ctx->user_port = bpf_ntohl(sock->dport << 16);
    bpf_printk("getpeer4 %d: %d -> %d", ctx->protocol, cookie, bpf_ntohl(ctx->user_port) >> 16);
    return 1;
}

SEC("cgroup/getpeername4")
int bpf_getpeername4(struct bpf_sock_addr *ctx) {
    return getpeer4(ctx);
}


SEC("cgroup/recvmsg4")
int bpf_recvmsg4(struct bpf_sock_addr *ctx) {
    return getpeer4(ctx);
}

__always_inline int getpeer6(struct bpf_sock_addr* ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) == proxy_pid) return 1;
    if (bpf_ntohl(ctx->user_port) >> 16 != proxy_port6) return 1;
    if (ctx->user_family != AF_INET6) return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_addr *sock = bpf_map_lookup_elem(&sock_map, &cookie);
    if (!sock) {
        return 1;
    }
    ctx->user_ip6[0] = sock->dip6[0];
    ctx->user_ip6[1] = sock->dip6[1];
    ctx->user_ip6[2] = sock->dip6[2];
    ctx->user_ip6[3] = sock->dip6[3];
    ctx->user_port = bpf_ntohs(sock->dport);
    bpf_printk("getpeer6 %d: %d -> %d", ctx->protocol, cookie, bpf_ntohl(ctx->user_port) >> 16);
    return 1;
}


SEC("cgroup/getpeername6")
int bpf_getpeername6(struct bpf_sock_addr *ctx) {
    return getpeer6(ctx);
}

SEC("cgroup/recvmsg6")
int bpf_recvmsg6(struct bpf_sock_addr *ctx) {
    return getpeer6(ctx);
}

SEC("cgroup/sock_release")
int bpf_sock_release(struct bpf_sock *ctx) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct sock_addr *sock = bpf_map_lookup_elem(&sock_map, &cookie);
    if (!sock) {
        return 1;
    }
    struct sock_key key = {
        .family = sock->family,
        .protocol = sock->protocol,
        .sport = sock->sport,
        .pad1 = 0,
    };
    bpf_printk("sock_release: %d: %d, %d, %d", cookie, key.family, key.protocol, key.sport);
    bpf_map_delete_elem(&cookie_map, &key);
    bpf_map_delete_elem(&sock_map, &cookie);
    return 1;
}


__always_inline struct sock_addr* find_sock(struct bpf_sockopt* ctx) {
    struct sock_key key = {
        .family = ctx->sk->family,
        .protocol = ctx->sk->protocol,
        .sport = bpf_ntohs(ctx->sk->dst_port),
        .pad1 = 0,
    };
    __u64 *cookie = bpf_map_lookup_elem(&cookie_map, &key);
    if (cookie) {
        return bpf_map_lookup_elem(&sock_map, cookie);
    } else {
        if(key.family != AF_INET6) return NULL;

        // IPV4 mapped IPV6
        key.family = AF_INET;
        cookie = bpf_map_lookup_elem(&cookie_map, &key);
        if(!cookie) return NULL;

        return bpf_map_lookup_elem(&sock_map, cookie);
    }
}

struct pinfo{
    pid_t pid;
    char comm[16];
}__attribute__((packed));

SEC("cgroup/getsockopt")
int bpf_sockopt(struct bpf_sockopt *ctx) {
    if ((bpf_get_current_pid_tgid() >> 32) != proxy_pid) return 1;
    if (ctx->optname != SO_ORIGINAL_DST && ctx->optname != 0xff) return 1;
    ctx->retval = 6;

    struct sock_addr *sock = find_sock(ctx);
    if (!sock) {
        bpf_printk("cannt found: %d, %d, %d", ctx->sk->family, ctx->sk->protocol, bpf_ntohs(ctx->sk->dst_port));
        return 1;
    }
    if(ctx->optname == 0xff) {
        struct pinfo *pi = ctx->optval;
        if ((void*)(pi + 1) > ctx->optval_end) return 1;
        __builtin_memcpy(pi, &sock->pid, sizeof(struct pinfo));
    }else if(ctx->sk->family == AF_INET) {
        struct sockaddr_in *sa = ctx->optval;
        if ((void*)(sa + 1) > ctx->optval_end) return 1;

        ctx->optlen = sizeof(*sa);
        sa->sin_family = ctx->sk->family;
        sa->sin_addr.s_addr = sock->dip4;
        sa->sin_port = bpf_htons(sock->dport);
    } else if(sock->family == AF_INET6){
        struct sockaddr_in6 *sa = ctx->optval;
        if ((void*)(sa + 1) > ctx->optval_end) return 1;

        ctx->optlen = sizeof(*sa);
        sa->sin6_family = ctx->sk->family;
        sa->sin6_addr.in6_u.u6_addr32[0] = sock->dip6[0];
        sa->sin6_addr.in6_u.u6_addr32[1] = sock->dip6[1];
        sa->sin6_addr.in6_u.u6_addr32[2] = sock->dip6[2];
        sa->sin6_addr.in6_u.u6_addr32[3] = sock->dip6[3];
        sa->sin6_port = bpf_htons(sock->dport);
    } else {
        //mapped ipv4
        struct sockaddr_in6 *sa = ctx->optval;
        if ((void*)(sa + 1) > ctx->optval_end) return 1;

        ctx->optlen = sizeof(*sa);
        sa->sin6_family = ctx->sk->family;
        sa->sin6_addr.in6_u.u6_addr32[0] = 0;
        sa->sin6_addr.in6_u.u6_addr32[1] = 0;
        sa->sin6_addr.in6_u.u6_addr32[2] = bpf_htonl(0xffff);
        sa->sin6_addr.in6_u.u6_addr32[3] = sock->dip4;
        sa->sin6_port = bpf_htons(sock->dport);
    }

    ctx->retval = 0;
    return 1;
}

