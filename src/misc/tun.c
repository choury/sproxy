#include "common/common.h"
#include "config.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <linux/ipv6.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>



static int set_if(struct ifreq *ifr) {
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
            LOGE("ioctl (SIOCSIFADDR) failed: %s\n", strerror(errno));
            break;
        }

        inet_pton(AF_INET, VPNMASK, &addr->sin_addr);
        if ((err = ioctl(fd, SIOCSIFNETMASK, ifr)) < 0) {
            LOGE("ioctl (SIOCSIFMASK) failed: %s\n", strerror(errno));
            break;
        }

        if ((err = ioctl(fd, SIOCGIFFLAGS, ifr)) < 0) {
            LOGE("ioctl (SIOCGIFFLAGS) failed: %s\n", strerror(errno));
            break;
        }

        ifr->ifr_flags |= IFF_UP;
        ifr->ifr_flags |= IFF_RUNNING;

        if ((err = ioctl(fd, SIOCSIFFLAGS, ifr)) < 0) {
            LOGE("ioctl (SIOCSIFFLAGS) failed: %s\n", strerror(errno));
            break;
        }

        ifr->ifr_mtu = BUF_LEN;
        if ((err = ioctl(fd, SIOCSIFMTU, ifr)) < 0) {
            LOGE("ioctl (SIOCSIFMTU) failed: %s\n", strerror(errno));
            break;
        }

        ifr->ifr_qlen = 1000;
        // 使用SIOCSIFTXQLEN命令设置发送队列长度
        if ((err = ioctl(fd, SIOCSIFTXQLEN, ifr)) < 0) {
            LOGE("ioctl(SIOCSIFTXQLEN) failed: %s\n", strerror(errno));
            //这个错误可以容忍，暂时忽略
            err = 0;
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
                LOGE("ioctl (SIOCADDRT) for dns failed: %s\n", strerror(errno));
                break;
            }
        }
    } while (0);
    close(fd);
    return err;
}

static int set_if6(struct ifreq *ifr) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if(fd < 0){
        return fd;
    }

    int err = 0;
    do {
        if ((err = ioctl(fd, SIOGIFINDEX, ifr)) < 0) {
            LOGE("ioctl (SIOGIFINDEX) failed: %s\n", strerror(errno));
            break;
        }

        /* set ip of this end point of tunnel */
        struct in6_ifreq ifr6;
        ifr6.ifr6_ifindex = ifr->ifr_ifindex;
        ifr6.ifr6_prefixlen = 111;
        inet_pton(AF_INET6, VPNADDR6, &ifr6.ifr6_addr);
        if ((err = ioctl(fd, SIOCSIFADDR, &ifr6)) < 0) {
            LOGE("ioctl (SIOCSIFADDR) failed: %s\n", strerror(errno));
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
                LOGE("ioctl (SIOCADDRT) for dns failed: %s\n", strerror(errno));
                break;
            }
        }
    } while (0);
    close(fd);
    return err;
}

#ifndef TUN_F_USO4
#define TUN_F_USO4	0x20	/* I can handle USO for IPv4 packets */
#endif
#ifndef TUN_F_USO6
#define TUN_F_USO6	0x40	/* I can handle USO for IPv6 packets */
#endif

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
            LOGE("ioctl (TUNSETIFF) failed: %s\n", strerror(errno));
            break;
        }
        if (flags & IFF_VNET_HDR) {
            size_t len = sizeof(struct virtio_net_hdr_v1);
            if ((err = ioctl(fd, TUNSETVNETHDRSZ, &len)) < 0) {
                LOGE("ioctl (TUNSETVNETHDRSZ) failed: %s\n", strerror(errno));
                break;
            }
            unsigned off_flags = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
            if ((err = ioctl(fd, TUNSETOFFLOAD, off_flags)) < 0){
                LOGE("ioctl(TUNSETOFFLOAD) failed: %s\n", strerror(errno));
                break;
            }
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

/*
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

*/
