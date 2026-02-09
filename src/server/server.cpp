#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "prot/quic/quic_server.h"
#endif
#include "req/cli.h"
#include "req/rguest2.h"
#include "req/rguest3.h"
#include "misc/config.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "prot/tls.h"
#include "bpf/bpf.h"

#include <unistd.h>
#include <assert.h>
#include <openssl/err.h>
#include <sys/socket.h>

#if __linux__
#include <linux/if_tun.h>
#include <net/if.h>
#include "req/guest_vpn.h"
#include "req/guest_tproxy.h"
int protectFd(int fd, const sockaddr_storage* addr){
    if(opt.interface && strlen(opt.interface) && !isLoopBack(addr)){
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", opt.interface);
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
            return 0;
        }
    }
    if(opt.fwmark) {
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, (void *)&opt.fwmark, sizeof(opt.fwmark)) < 0) {
            return 0;
        }
    }
    return 1;
}

#else
//do nothing, useful for vpn only
int protectFd(int, const sockaddr_storage*){
    return 1;
}
#endif

static sockaddr_in localhost4 = {
    .sin_family = AF_INET,
    .sin_port = 0,
    .sin_addr = {htonl(INADDR_LOOPBACK)},
    .sin_zero = {},
 };

//::1
static sockaddr_in6 localhost6 = {
    .sin6_family = AF_INET6,
    .sin6_port = 0,
    .sin6_flowinfo = 0,
    .sin6_addr = IN6ADDR_LOOPBACK_INIT,
    .sin6_scope_id = 0,
};


static int ListenLocalhostTcp(uint16_t port, int fd[2], const listenOption* ops) {
    fd[0] = fd[1] = -1;
    localhost4.sin_port = htons(port);
    fd[0] = ListenTcp((sockaddr_storage*)&localhost4, ops);
    localhost6.sin6_port = htons(port);
    fd[1] = ListenTcp((sockaddr_storage*)&localhost6, ops);
    if(fd[0] < 0 || fd[1] < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    return 0;
}

static int ListenLocalhostUdp(uint16_t port, int fd[2], const listenOption* ops) {
    fd[0] = fd[1] = -1;
    localhost4.sin_port = htons(port);
    fd[0] = ListenUdp((sockaddr_storage*)&localhost4, ops);
    localhost6.sin6_port = htons(port);
    fd[1] = ListenUdp((sockaddr_storage*)&localhost6, ops);
    if(fd[0] < 0 || fd[1] < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    Sign sign;
    sign.add(SIGHUP,  (sig_t)reloadstrategy);
    sign.add(SIGUSR1, (sig_t)(void(*)())dump_stat);
    //sign.add(SIGUSR2, (sig_t)exit_loop);
    sign.add(SIGTERM, (sig_t)exit_loop);
    sign.add(SIGINT,  (sig_t)exit_loop);
#if Backtrace_FOUND
    signal(SIGABRT, dump_trace);
#endif
    std::vector<std::shared_ptr<Ep>> servers;
    if(opt.rproxy_name) {
#ifdef HAVE_QUIC
        // 根据协议选择rguest2还是rguest3
        if(strcmp(opt.Server.protocol, "quic") == 0) {
            LOG("Starting rproxy3 client to %s\n", dumpDest(opt.Server).c_str());
            new Rguest3(opt.Server, opt.rproxy_name);
        } else
#endif
        {
            LOG("Starting rproxy2 client to %s\n", dumpDest(opt.Server).c_str());
            new Rguest2(opt.Server, opt.rproxy_name);
        }
    }

    if(opt.http_list) {
        for(struct dest_list* node = opt.http_list; node; node = node->next) {
            const struct Destination& dest = node->dest;
            int fd[2] = {-1, -1};
            if(dest.systemd_fd >= 0) {
                fd[0] = dest.systemd_fd;
            } else if(strcmp(dest.hostname, "localhost") == 0) {
                if(ListenLocalhostTcp(dest.port, fd, nullptr) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenTcpD(&dest, nullptr);
                if (fd[0] < 0) {
                    return -1;
                }
            }
            servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[0], nullptr));
            if(fd[1] >= 0) {
                servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[1], nullptr));
            }
            if(dest.systemd_fd >= 0) {
                LOG("listen on systemd fd %d for http\n", fd[0]);
            } else {
                LOG("listen on %s:%d for http\n", dest.hostname, (int)dest.port);
            }
        }
    }
#if __linux__
    if(opt.tproxy.hostname[0]) {
        int fd[4] = {-1, -1, -1, -1};
        listenOption ops = {
            .disable_defer_accepct = true,
            .enable_ip_transparent = !opt.bpf_cgroup,
        };
        if(strcmp(opt.tproxy.hostname, "localhost") == 0) {
            if(ListenLocalhostTcp(opt.tproxy.port, fd, &ops) < 0) {
                return -1;
            }
            if(ListenLocalhostUdp(opt.tproxy.port, fd+2, &ops) < 0) {
                return -1;
            }
#ifdef HAVE_BPF
            if(opt.bpf_cgroup && load_bpf(opt.bpf_cgroup, &localhost4, &localhost6, (uint32_t)opt.bpf_fwmark)){
                return -1;
            }
#endif
        } else {
            fd[0] = ListenTcpD(&opt.tproxy, &ops);
            if (fd[0] < 0) {
                return -1;
            }
            fd[2] = ListenUdpD(&opt.tproxy, &ops);
            if (fd[2] < 0) {
                return -1;
            }
#ifdef HAVE_BPF
            if(opt.bpf_cgroup) {
                if(strcmp(opt.tproxy.hostname, "[::]") == 0){
                    localhost4.sin_port = htons(opt.tproxy.port);
                    localhost6.sin6_port = htons(opt.tproxy.port);
                    if(load_bpf(opt.bpf_cgroup, &localhost4, &localhost6, (uint32_t)opt.bpf_fwmark)) {
                        return -1;
                    }
                }else {
                    sockaddr_storage addr;
                    storage_aton(opt.tproxy.hostname, opt.tproxy.port, &addr);
                    if(addr.ss_family == AF_INET
                        && load_bpf(opt.bpf_cgroup, (sockaddr_in*)&addr, &localhost6, (uint32_t)opt.bpf_fwmark))
                    {
                        return -1;
                    }
                    if(addr.ss_family == AF_INET6
                        && load_bpf(opt.bpf_cgroup, &localhost4, (sockaddr_in6*)&addr, (uint32_t)opt.bpf_fwmark))
                    {
                        return -1;
                    }
                }
            }
#endif // HAVE_BPF
        }
        servers.emplace_back(std::make_shared<Tproxy_server>(fd[0]));
        if(fd[1] >= 0) servers.emplace_back(std::make_shared<Tproxy_server>(fd[1]));
        servers.emplace_back(std::make_shared<Tproxy_server>(fd[2]));
        if(fd[3] >= 0) servers.emplace_back(std::make_shared<Tproxy_server>(fd[3]));
        LOG("listen on %s:%d for tproxy\n", opt.tproxy.hostname, (int)opt.tproxy.port);
    }
#ifdef HAVE_BPF
    else if(opt.bpf_cgroup && load_bpf(opt.bpf_cgroup, nullptr, nullptr, (uint32_t)opt.bpf_fwmark)) {
        return -1;
    }
#endif
#endif // __linux__
    if(opt.ssl_list) {
        for(struct dest_list* node = opt.ssl_list; node; node = node->next) {
            const struct Destination& dest = node->dest;
            int fd[2] = {-1, -1};
            if(dest.systemd_fd >= 0) {
                fd[0] = dest.systemd_fd;
            } else if(strcmp(dest.hostname, "localhost") == 0) {
                if(ListenLocalhostTcp(dest.port, fd, nullptr) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenTcpD(&dest, nullptr);
                if (fd[0] < 0) {
                    return -1;
                }
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(fd[0], nullptr));
                if(fd[1] >= 0) {
                    servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(fd[1], nullptr));
                }
                if(dest.systemd_fd >= 0) {
                    LOG("listen on systemd fd %d for ssl\n", fd[0]);
                } else {
                    LOG("listen on %s:%d for ssl sni\n", dest.hostname, (int)dest.port);
                }
            } else {
                SSL_CTX * ctx = initssl(false, nullptr);
                servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[0], ctx));
                if(fd[1] >= 0) {
                    servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[1], ctx));
                }
                if(dest.systemd_fd >= 0) {
                    LOG("listen on systemd fd %d for ssl\n", fd[0]);
                } else {
                    LOG("listen on %s:%d for ssl\n", dest.hostname, (int)dest.port);
                }
            }
        }
    }
#ifdef HAVE_QUIC
    generate_reset_secret();
    if(opt.quic_list) {
        for(struct dest_list* node = opt.quic_list; node; node = node->next) {
            const struct Destination& dest = node->dest;
            int fd[2] = {-1, -1};
            if(dest.systemd_fd >= 0) {
                fd[0] = dest.systemd_fd;
            } else if(strcmp(dest.hostname, "localhost") == 0) {
                if(ListenLocalhostUdp(dest.port, fd, nullptr) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenUdpD(&dest, nullptr);
                if(fd[0] <  0) {
                    return -1;
                }
            }
            if(dest.systemd_fd >= 0) {
                sockaddr_storage addr;
                socklen_t addr_len = sizeof(addr);
                if(getsockname(fd[0], (sockaddr*)&addr, &addr_len) < 0) {
                    LOGE("systemd socket getsockname failed for %d: %s\n", fd[0], strerror(errno));
                    continue;
                }
                SetUdpOptions(fd[0], &addr);
                SetRecvPKInfo(fd[0], &addr);
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Quic_sniServer>(fd[0], dest.port));
                if(fd[1] >= 0) {
                    servers.emplace_back(std::make_shared<Quic_sniServer>(fd[1], dest.port));
                }
                if(dest.systemd_fd >= 0) {
                    LOG("listen on systemd fd %d for quic\n", fd[0]);
                } else {
                    LOG("listen on %s:%d for quic sni\n", dest.hostname, (int)dest.port);
                }
            }else {
                SSL_CTX * ctx = initssl(true, nullptr);
                servers.emplace_back(std::make_shared<Quic_server>(fd[0], dest.port, ctx));
                if(fd[1] >= 0) {
                    servers.emplace_back(std::make_shared<Quic_server>(fd[1], dest.port, ctx));
                }
                if(dest.systemd_fd >= 0) {
                    LOG("listen on systemd fd %d for quic\n", fd[0]);
                } else {
                    LOG("listen on %s:%d for quic\n", dest.hostname, (int)dest.port);
                }
            }
        }
    }
#endif
#if __linux__
    if(opt.tun_mode) {
        char tun_name[IFNAMSIZ] = {0};
        int tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI | IFF_NAPI | IFF_VNET_HDR);
        if (tun < 0) {
            LOGE("failed to create tun: %s\n", strerror(errno));
            return -1;
        }
        new Guest_vpn(tun, true);
        LOG("listen on %s for vpn\n", tun_name);
    }
    if(opt.tun_fd >= 0) {
        new Guest_vpn(opt.tun_fd, false);
        LOG("listen on %d for vpn\n", opt.tun_fd);
    }
#endif // __linux__
    if(opt.admin.hostname[0]){
        int fd[2] = {-1, -1};
        if(opt.admin.port == 0){
            fd[0] = ListenUnix(opt.admin.hostname, nullptr);
            if (fd[0] < 0) {
                return -1;
            }
        }else if(strcmp(opt.admin.hostname, "localhost") == 0){
            if(ListenLocalhostTcp(opt.admin.port, fd, nullptr) < 0) {
                return -1;
            }
        }else {
            fd[0] = ListenTcpD(&opt.admin, nullptr);
            if (fd[0] < 0) {
                return -1;
            }
        }
        if(opt.admin.port) {
            LOG("listen on %s:%d for admin\n", opt.admin.hostname, (int)opt.admin.port);
        } else {
            LOG("listen on %s for admin\n", opt.admin.hostname);
        }
        servers.emplace_back(std::make_shared<Cli_server>(fd[0]));
        if(fd[1] >= 0) servers.emplace_back(std::make_shared<Cli_server>(fd[1]));
    }
    LOG("Accepting connections ...\n");
    uint64_t idle_ms = 0;
    const uint64_t systemd_idle_exit_ms = 5 * 60 * 1000;
    while (will_contiune) {
        uint32_t msec = 0;
        while(msec == 0) msec = do_delayjob();
        int handled = event_loop(msec);
        if(handled < 0){
            return 6;
        }
        if(handled) {
            idle_ms = 0;
            continue;
        }
        idle_ms += msec;
        if(opt.systemd_socket && idle_ms >= systemd_idle_exit_ms) {
            LOG("systemd socket idle timeout, exiting ...\n");
            exit_loop(0);
        }
    }
    LOG("Sproxy exiting ...\n");
    neglect();
#ifdef HAVE_BPF
    if(opt.bpf_cgroup) {
        unload_bpf();
    }
#endif
    return 0;
}
