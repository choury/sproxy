#include "vpn.h"
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>

const char* out_interface;

void protectFd(int fd) {
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), out_interface);
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("bind interface");
    }
}

int tun_create(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;

    assert(dev != NULL);

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

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

    int tmp_fd = socket( AF_INET, SOCK_DGRAM, 0);

    /* set ip of this end point of tunnel */
    ifr.ifr_addr.sa_family = AF_INET;
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    inet_pton(AF_INET, "10.0.0.1", &addr->sin_addr);
    if((err = ioctl(tmp_fd, SIOCSIFADDR, &ifr)) < 0 ) {
        perror("ioctl (SIOCSIFADDR) failed");
        close(fd);
        close(tmp_fd);
        return err;
    }

    inet_pton(AF_INET, "255.255.255.255", &addr->sin_addr);
    if((err = ioctl(tmp_fd, SIOCSIFNETMASK, &ifr)) < 0) {
        perror("ioctl (SIOCSIFMASK) failed");
        close(fd);
        close(tmp_fd);
        return err;
    }

    if((err = ioctl(tmp_fd, SIOCGIFFLAGS, &ifr)) < 0 ) {
        perror("ioctl (SIOCGIFFLAGS) failed");
        close(fd);
        close(tmp_fd);
        return err;

    }

    ifr.ifr_flags |= IFF_UP;
    ifr.ifr_flags |= IFF_RUNNING;

    if ((err = ioctl(tmp_fd, SIOCSIFFLAGS, &ifr)) < 0 ) {
        perror("ioctl (SIOCSIFFLAGS) failed");
        close(fd);
        close(tmp_fd);
        return err;

    }

    ifr.ifr_mtu = VPN_MTU;
    if((err = ioctl(tmp_fd, SIOCSIFMTU, &ifr)) < 0) {
        perror("ioctl (SIOCSIFMTU) failed");
        close(fd);
        close(tmp_fd);
        return err;
    }

    /* make tun socket non blocking */
    uint32_t sock_opts = fcntl(fd, F_GETFL, 0 );
    fcntl(fd, F_SETFL, sock_opts | O_NONBLOCK );

    close(tmp_fd);
    return fd;
}


int main(int argc, char** argv) {
    if(argc < 2){
        fprintf(stderr, "usage: %s interface\n", argv[0]);
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
    vpn_start(tun);
    return 0;
}
