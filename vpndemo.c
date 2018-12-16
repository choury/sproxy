#include "vpn.h"
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <string.h>
#include <signal.h>


int daemon_mode = 0;
const char* out_interface;

int protectFd(int fd) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), out_interface);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        return 0;
    }
    return 1;
}

int set_if(struct ifreq* ifr){
    int err;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* set ip of this end point of tunnel */
    ifr->ifr_addr.sa_family = AF_INET;
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr->ifr_addr;
    inet_pton(AF_INET, "10.1.0.1", &addr->sin_addr);
    if((err = ioctl(fd, SIOCSIFADDR, ifr)) < 0) {
        perror("ioctl (SIOCSIFADDR) failed");
        close(fd);
        return err;
    }

    inet_pton(AF_INET, "255.255.255.255", &addr->sin_addr);
    if((err = ioctl(fd, SIOCSIFNETMASK, ifr)) < 0) {
        perror("ioctl (SIOCSIFMASK) failed");
        close(fd);
        return err;
    }

    if((err = ioctl(fd, SIOCGIFFLAGS, ifr)) < 0) {
        perror("ioctl (SIOCGIFFLAGS) failed");
        close(fd);
        return err;

    }

    ifr->ifr_flags |= IFF_UP;
    ifr->ifr_flags |= IFF_RUNNING;

    if ((err = ioctl(fd, SIOCSIFFLAGS, ifr)) < 0) {
        perror("ioctl (SIOCSIFFLAGS) failed");
        close(fd);
        return err;
    }

    ifr->ifr_mtu = VPN_MTU;
    if((err = ioctl(fd, SIOCSIFMTU, ifr)) < 0) {
        perror("ioctl (SIOCSIFMTU) failed");
        close(fd);
        return err;
    }

    struct rtentry route;
    memset(&route, 0, sizeof(route));

    addr = (struct sockaddr_in *)&route.rt_gateway;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr("10.1.0.1");

    addr = (struct sockaddr_in*)&route.rt_dst;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    addr = (struct sockaddr_in*)&route.rt_genmask;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = INADDR_ANY;

    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = ifr->ifr_name;

    if((err = ioctl(fd, SIOCADDRT, &route)) < 0){
        perror("ioctl (SIOCADDRT) failed");
        close(fd);
        return err;
    }
    struct DnsConfig config;
    getDnsConfig(&config);
    for(int i = 0; i < config.namecount; i++){
        if(config.server[i].addr_in.sin_family != AF_INET){
            continue;
        }
        memcpy(&route.rt_dst, &config.server[i], sizeof(struct sockaddr_in));
        addr = (struct sockaddr_in*)&route.rt_genmask;
        inet_pton(AF_INET, "255.255.255.255", &addr->sin_addr);
        if((err = ioctl(fd, SIOCADDRT, &route)) < 0){
            perror("ioctl (SIOCADDRT) for dns failed");
            close(fd);
            return err;
        }
    }
    close(fd);
    return 0;
}

int set_if6(struct ifreq* ifr){
    int err;

    int fd = socket(AF_INET6, SOCK_DGRAM, 0);
    if ((err = ioctl(fd, SIOGIFINDEX, ifr)) < 0) {
        perror("ioctl (SIOGIFINDEX) failed");
        close(fd);
        return err;
    }

    /* set ip of this end point of tunnel */
    struct in6_ifreq ifr6;
    ifr6.ifr6_ifindex = ifr->ifr_ifindex;
    ifr6.ifr6_prefixlen = 128;
    //inet_pton(AF_INET6, "::ffff:10.1.0.1", &ifr6.ifr6_addr);
    inet_pton(AF_INET6, "fd00::abcd", &ifr6.ifr6_addr);
    if((err = ioctl(fd, SIOCSIFADDR, &ifr6)) < 0) {
        perror("ioctl (SIOCSIFADDR) failed");
        close(fd);
        return err;
    }

    if((err = ioctl(fd, SIOCGIFFLAGS, ifr)) < 0) {
        perror("ioctl (SIOCGIFFLAGS) failed");
        close(fd);
        return err;

    }

    ifr->ifr_flags |= IFF_UP;
    ifr->ifr_flags |= IFF_RUNNING;

    if ((err = ioctl(fd, SIOCSIFFLAGS, ifr)) < 0) {
        perror("ioctl (SIOCSIFFLAGS) failed");
        close(fd);
        return err;
    }


    struct in6_rtmsg route;
    memset(&route, 0, sizeof(route));

    inet_pton(AF_INET6, "fd00::abcd", &route.rtmsg_gateway);
    route.rtmsg_dst = in6addr_any;
    //route.rtmsg_flags = RTF_UP | RTF_GATEWAY;
    route.rtmsg_flags = RTF_UP;
    route.rtmsg_metric = 1;
    route.rtmsg_ifindex = ifr6.ifr6_ifindex;

    if((err = ioctl(fd, SIOCADDRT, &route)) < 0){
        perror("ioctl (SIOCADDRT) failed");
        close(fd);
        return err;
    }

    struct DnsConfig config;
    getDnsConfig(&config);
    for(int i = 0; i < config.namecount; i++){
        if(config.server[i].addr_in6.sin6_family != AF_INET6){
            continue;
        }
        route.rtmsg_dst = config.server[i].addr_in6.sin6_addr;
        route.rtmsg_dst_len = 128;
        if((err = ioctl(fd, SIOCADDRT, &route)) < 0){
            perror("ioctl (SIOCADDRT) for dns failed");
            close(fd);
            return err;
        }
    }
    close(fd);
    return 0;
}

int tun_create(char *dev, int flags) {
    int fd, err;

    assert(dev != NULL);
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags |= flags;
    if (*dev != '\0')
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl");
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);

    if(set_if(&ifr)){
        close(fd);
        return -1;
    }

    if(set_if6(&ifr)){
        close(fd);
        return -1;
    }
    return fd;
}


int main(int argc, char** argv) {
    if(argc < 3){
        fprintf(stderr, "usage: %s interface server [secret]\n", argv[0]);
        return -1;
    }
    out_interface = argv[1];
    char tun_name[IFNAMSIZ]= {0};
    int tun = tun_create(tun_name, IFF_TUN | IFF_NO_PI);
    if (tun < 0) {
        perror("tun_create");
        return 1;
    }
    fprintf(stderr, "TUN name is %s\n", tun_name);
    struct VpnConfig vpn;
    vpn.disable_ipv6 = 1;
    vpn.ignore_cert_error = 1;
    vpn.secret[0] = 0;
    strcpy(vpn.server, argv[2]);
    signal(SIGUSR2, vpn_reload);
    if(argc >= 4){
        strcpy(vpn.secret, argv[3]);
        printf("set secret to: %s\n", vpn.secret);
    }
    vpn.fd = tun;
    vpn_start(&vpn);
    return 0;
}
