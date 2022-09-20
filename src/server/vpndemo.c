#include "vpn.h"
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/if_tun.h>


int protectFd(int fd) {
    if(opt.interface == NULL){
        return 0;
    }
    if(strlen(opt.interface) == 0) {
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

int set_if(struct ifreq *ifr) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0){
        return fd;
    }

    int err = 0;
    do {
        /* set ip of this end point of tunnel */
        ifr->ifr_addr.sa_family = AF_INET;
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr->ifr_addr;
        inet_pton(AF_INET, VPNADDR, &addr->sin_addr);
        if ((err = ioctl(fd, SIOCSIFADDR, ifr)) < 0) {
            perror("ioctl (SIOCSIFADDR) failed");
            break;
        }

        inet_pton(AF_INET, VPNMASK, &addr->sin_addr);
        if ((err = ioctl(fd, SIOCSIFNETMASK, ifr)) < 0) {
            perror("ioctl (SIOCSIFMASK) failed");
            break;
        }

        if ((err = ioctl(fd, SIOCGIFFLAGS, ifr)) < 0) {
            perror("ioctl (SIOCGIFFLAGS) failed");
            break;
        }

        ifr->ifr_flags |= IFF_UP;
        ifr->ifr_flags |= IFF_RUNNING;

        if ((err = ioctl(fd, SIOCSIFFLAGS, ifr)) < 0) {
            perror("ioctl (SIOCSIFFLAGS) failed");
            break;
        }

        ifr->ifr_mtu = BUF_LEN;
        if ((err = ioctl(fd, SIOCSIFMTU, ifr)) < 0) {
            perror("ioctl (SIOCSIFMTU) failed");
            break;
        }
        if (!opt.set_dns_route) {
            break;
        }

        struct rtentry route;
        memset(&route, 0, sizeof(route));

        route.rt_flags = RTF_UP | RTF_GATEWAY;
        route.rt_dev = ifr->ifr_name;

        addr = (struct sockaddr_in *)&route.rt_gateway;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = inet_addr(VPNADDR);

        addr = (struct sockaddr_in *)&route.rt_dst;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_ANY;

        addr = (struct sockaddr_in *)&route.rt_genmask;
        addr->sin_family = AF_INET;
        addr->sin_addr.s_addr = INADDR_ANY;

        struct DnsConfig config;
        getDnsConfig(&config);
        for (size_t i = 0; i < config.namecount; i++) {
            if (config.server[i].ss_family != AF_INET) {
                continue;
            }
            memcpy(&route.rt_dst, &config.server[i], sizeof(struct sockaddr_in));
            addr = (struct sockaddr_in *)&route.rt_genmask;
            inet_pton(AF_INET, "255.255.255.255", &addr->sin_addr);
            if ((err = ioctl(fd, SIOCADDRT, &route)) < 0) {
                perror("ioctl (SIOCADDRT) for dns failed");
                break;
            }
        }
    } while (0);
    close(fd);
    return err;
}


struct in6_ifreq {
    struct in6_addr ifr6_addr;
    __u32 ifr6_prefixlen;
    unsigned int ifr6_ifindex;
};

int set_if6(struct ifreq *ifr) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0){
        return fd;
    }

    int err = 0;
    do {
        if ((err = ioctl(fd, SIOGIFINDEX, ifr)) < 0) {
            perror("ioctl (SIOGIFINDEX) failed");
            break;
        }

        /* set ip of this end point of tunnel */
        struct in6_ifreq ifr6;
        ifr6.ifr6_ifindex = ifr->ifr_ifindex;
        ifr6.ifr6_prefixlen = 111;
        inet_pton(AF_INET6, VPNADDR6, &ifr6.ifr6_addr);
        if ((err = ioctl(fd, SIOCSIFADDR, &ifr6)) < 0) {
            perror("ioctl (SIOCSIFADDR) failed");
            break;
        }

        if ((err = ioctl(fd, SIOCGIFFLAGS, ifr)) < 0) {
            perror("ioctl (SIOCGIFFLAGS) failed");
            break;
        }

        ifr->ifr_flags |= IFF_UP;
        ifr->ifr_flags |= IFF_RUNNING;

        if ((err = ioctl(fd, SIOCSIFFLAGS, ifr)) < 0) {
            perror("ioctl (SIOCSIFFLAGS) failed");
            break;
        }

        if(!opt.set_dns_route){
            break;
        }

        struct in6_rtmsg route;
        memset(&route, 0, sizeof(route));

        inet_pton(AF_INET6, VPNADDR6, &route.rtmsg_gateway);
        //route.rtmsg_flags = RTF_UP | RTF_GATEWAY;
        route.rtmsg_flags = RTF_UP;
        route.rtmsg_metric = 1;
        route.rtmsg_ifindex = ifr6.ifr6_ifindex;
        route.rtmsg_dst = in6addr_any;

        struct DnsConfig config;
        getDnsConfig(&config);
        for (size_t i = 0; i < config.namecount; i++) {
            if (config.server[i].ss_family != AF_INET6) {
                continue;
            }
            struct sockaddr_in6* addr6 = (struct sockaddr_in6*)&config.server[i];
            route.rtmsg_dst = addr6->sin6_addr;
            route.rtmsg_dst_len = 128;
            if ((err = ioctl(fd, SIOCADDRT, &route)) < 0) {
                perror("ioctl (SIOCADDRT) for dns failed");
                break;
            }
        }
    } while (0);
    close(fd);
    return err;
}

int tun_create(char *dev, int flags) {
    assert(dev != NULL);

    int fd;
    if ((fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) < 0) {
        return fd;
    }

    int err = 0;
    do {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags |= flags;
        if (*dev != '\0')
            strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
        if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
            perror("ioctl");
            break;
        }
        strcpy(dev, ifr.ifr_name);

        if ((err = set_if(&ifr)) < 0) {
            break;
        }

        if (!opt.ipv6_enabled) {
            return fd;
        }

        if ((err = set_if6(&ifr)) < 0) {
            break;
        }
    } while (0);

    if (err) {
        close(fd);
        return err;
    }
    return fd;
}

int main(int argc, char** argv) {
    parseConfig(argc, argv);
    if (opt.interface == NULL) {
        LOGE("interface must be set for vpn\n");
        return ENOENT;
    }
    char tun_name[IFNAMSIZ] = {0};
    int tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun < 0) {
        int e = errno;
        LOGE("tun_create: %s\n", strerror(e));
        return e;
    }
    LOG("TUN name is %s\n", tun_name);
    vpn_start(tun);
    return 0;
}
