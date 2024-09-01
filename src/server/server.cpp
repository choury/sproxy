#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "prot/quic/quic_server.h"
#endif
#include "req/cli.h"
#include "req/rguest2.h"
#include "misc/job.h"
#include "misc/config.h"
#include "prot/tls.h"

#include <unistd.h>
#include <assert.h>
#include <openssl/err.h>

#if __linux__
#include <linux/if_tun.h>
#include <net/if.h>
#include "req/guest_vpn.h"
#include "req/guest_tproxy.h"
int protectFd(int fd) {
    if(opt.interface == NULL || strlen(opt.interface) == 0){
        return 1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", opt.interface);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        return 0;
    }
    return 1;
}

#else
//do nothing, useful for vpn only
int protectFd(int){
    return 1;
}
#endif

static int ListenTcp(const Destination* dest) {
    sockaddr_storage addr;
    if(storage_aton(dest->hostname, dest->port, &addr) == 0) {
        LOGE("failed to parse listen addr: %s\n", dest->hostname);
        return -1;
    }
    return ListenTcp(&addr);
}

static int ListenUdp(const Destination* dest) {
    sockaddr_storage addr;
    if(storage_aton(dest->hostname, dest->port, &addr) == 0) {
        LOGE("failed to parse listen addr: %s\n", dest->hostname);
        return -1;
    }
    int fd = ListenUdp(&addr);
    if(fd < 0) {
        return -1;
    }
    return fd;
}


static int ListenLocalhostTcp(uint16_t port, int fd[2]) {
    fd[0] = fd[1] = -1;
    sockaddr_storage addr;
    storage_aton("127.0.0.1", port, &addr);
    fd[0] = ListenTcp(&addr);
    storage_aton("[::1]", port, &addr);
    fd[1] = ListenTcp(&addr);
    if(fd[0] < 0 || fd[1] < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    return 0;
}

static int ListenLocalhostUdp(uint16_t port, int fd[2]) {
    fd[0] = fd[1] = -1;
    sockaddr_storage addr[2];
    storage_aton("127.0.0.1", port, &addr[0]);
    fd[0] = ListenUdp(&addr[0]);
    storage_aton("[::1]", port, &addr[1]);
    fd[1] = ListenUdp(&addr[1]);
    if(fd[0] < 0 || fd[1] < 0) {
        close(fd[0]);
        close(fd[1]);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    std::vector<std::shared_ptr<Ep>> servers;
    if(opt.rproxy_name) {
        new Rguest2(&opt.Server, opt.rproxy_name);
    }else {
        if(opt.http.hostname[0]){
            int fd[2] = {-1, -1};
            if(strcmp(opt.http.hostname, "localhost") == 0) {
                if(ListenLocalhostTcp(opt.http.port, fd) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenTcp(&opt.http);
                if (fd[0] < 0) {
                    return -1;
                }
            }
            servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[0], nullptr));
            if(fd[1] >= 0) servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[1], nullptr));
            LOG("listen on %s:%d for http\n", opt.http.hostname, (int)opt.http.port);
        }
#if __linux__
        if(opt.tproxy.hostname[0]) {
            int fd[4] = {-1, -1, -1, -1};
            if(strcmp(opt.tproxy.hostname, "localhost") == 0) {
                if(ListenLocalhostTcp(opt.tproxy.port, fd) < 0) {
                    return -1;
                }
                if(ListenLocalhostUdp(opt.tproxy.port, fd+2) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenTcp(&opt.tproxy);
                if (fd[0] < 0) {
                    return -1;
                }
                fd[2] = ListenUdp(&opt.tproxy);
                if (fd[2] < 0) {
                    return -1;
                }
            }
            servers.emplace_back(std::make_shared<Tproxy_server>(fd[0]));
            if(fd[1] >= 0) servers.emplace_back(std::make_shared<Tproxy_server>(fd[1]));
            servers.emplace_back(std::make_shared<Tproxy_server>(fd[2]));
            if(fd[3] >= 0) servers.emplace_back(std::make_shared<Tproxy_server>(fd[3]));
            LOG("listen on %s:%d for tproxy\n", opt.tproxy.hostname, (int)opt.tproxy.port);
        }
#endif
        if(opt.ssl.hostname[0]) {
            int fd[2] = {-1, -1};
            if(strcmp(opt.ssl.hostname, "localhost") == 0) {
                if(ListenLocalhostTcp(opt.ssl.port, fd) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenTcp(&opt.ssl);
                if (fd[0] < 0) {
                    return -1;
                }
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(fd[0], nullptr));
                if(fd[1] >= 0) servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(fd[1], nullptr));
                LOG("listen on %s:%d for ssl sni\n", opt.ssl.hostname, (int)opt.ssl.port);
            }else {
                SSL_CTX * ctx = initssl(false, nullptr);
                servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[0], ctx));
                if(fd[1] >= 0) servers.emplace_back(std::make_shared<Http_server<Guest>>(fd[1], ctx));
                LOG("listen on %s:%d for ssl\n", opt.ssl.hostname, (int)opt.ssl.port);
            }
        }
#ifdef HAVE_QUIC
        if(opt.quic.hostname[0]) {
            int fd[2] = {-1, -1};
            if(strcmp(opt.quic.hostname, "localhost") == 0) {
                if(ListenLocalhostUdp(opt.quic.port, fd) < 0) {
                    return -1;
                }
            } else {
                fd[0] = ListenUdp(&opt.quic);
                if(fd[0] <  0) {
                    return -1;
                }
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Quic_sniServer>(fd[0]));
                if(fd[1] >= 0) servers.emplace_back(std::make_shared<Quic_sniServer>(fd[1]));
                LOG("listen on %s:%d for quic snil\n", opt.quic.hostname, (int)opt.quic.port);
            }else {
                SSL_CTX * ctx = initssl(true, nullptr);
                servers.emplace_back(std::make_shared<Quic_server>(fd[0], ctx));
                if(fd[1] >= 0) servers.emplace_back(std::make_shared<Quic_server>(fd[1], ctx));
                LOG("listen on %s:%d for quic\n", opt.quic.hostname, (int)opt.quic.port);
            }
        }
#endif
#if __linux__
        if(opt.tun_mode) {
            char tun_name[IFNAMSIZ] = {0};
            int tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
            if (tun < 0) {
                return -1;
            }
            new Guest_vpn(tun);
            LOG("listen on %s for vpn\n", tun_name);
        }
#endif
    }
    if(opt.admin.hostname[0]){
        int fd[2] = {-1, -1};
        if(opt.admin.port == 0){
            fd[0] = ListenUnix(opt.admin.hostname);
            if (fd[0] < 0) {
                return -1;
            }
        }else if(strcmp(opt.admin.hostname, "localhost") == 0){
            if(ListenLocalhostTcp(opt.admin.port, fd) < 0) {
                return -1;
            }
        }else {
            fd[0] = ListenTcp(&opt.admin);
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
    while (will_contiune) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            return 6;
        }
    }
    LOG("Sproxy exiting ...\n");
    neglect();
}
