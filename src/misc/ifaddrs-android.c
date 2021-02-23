#include <ifaddrs.h>

#if __ANDROID_API__ < 24
// Android (bionic) doesn't have getifaddrs(3)/freeifaddrs(3).
// We fake it here, so getlocalip can use that API
// with all the non-portable code being in this file.

#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>


// Sadly, we can't keep the interface index for portability with BSD.
// We'll have to keep the name instead, and re-query the index when
// we need it later.
static bool setNameAndFlagsByIndex(struct ifaddrs* addr, int interfaceIndex) {
    // Get the name.
    char buf[IFNAMSIZ];
    char* name = if_indextoname(interfaceIndex, buf);
    if (name == NULL) {
        return false;
    }
    addr->ifa_name = (char*)calloc(1, strlen(name) + 1);

    // Get the flags.
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
        return false;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, name);
    int rc = ioctl(fd, SIOCGIFFLAGS, &ifr);
    close(fd);
    if (rc == -1) {
        return false;
    }
    addr->ifa_flags = ifr.ifr_flags;
    return true;
}

// Returns a pointer to the first byte in the address data (which is
// stored in network byte order).
static uint8_t* sockaddrBytes(int family, struct sockaddr_storage* ss) {
    if (family == AF_INET) {
        struct sockaddr_in* ss4 = (struct sockaddr_in*)ss;
        return (uint8_t*)(&ss4->sin_addr);
    } else if (family == AF_INET6) {
        struct sockaddr_in6* ss6 = (struct sockaddr_in6*)ss;
        return (uint8_t*)(&ss6->sin6_addr);
    }
    return NULL;
}

// Netlink gives us the address family in the header, and the
// sockaddr_in or sockaddr_in6 bytes as the payload. We need to
// stitch the two bits together into the sockaddr that's part of
// our portable interface.
static void setAddress(struct ifaddrs* addr, int family, void* data, size_t byteCount) {
    // Set the address proper...
    struct sockaddr_storage* ss = (struct sockaddr_storage*)calloc(1, sizeof(struct sockaddr_storage));
    addr->ifa_addr = (struct sockaddr*)ss;
    ss->ss_family = family;
    uint8_t* dst = sockaddrBytes(family, ss);
    memcpy(dst, data, byteCount);
}

// Netlink gives us the prefix length as a bit count. We need to turn
// that into a BSD-compatible netmask represented by a sockaddr*.
static void setNetmask(struct ifaddrs* addr, int family, size_t prefixLength) {
    // ...and work out the netmask from the prefix length.
    struct sockaddr_storage* ss = (struct sockaddr_storage*)calloc(1, sizeof(struct sockaddr_storage));
    addr->ifa_netmask = (struct sockaddr*)ss;
    ss->ss_family = family;
    uint8_t* dst = sockaddrBytes(family, ss);
    memset(dst, 0xff, prefixLength / 8);
    if ((prefixLength % 8) != 0) {
        dst[prefixLength/8] = (0xff << (8 - (prefixLength % 8)));
    }
}


// FIXME: use iovec instead.
struct addrReq_struct {
    struct nlmsghdr netlinkHeader;
    struct ifaddrmsg msg;
};

static bool sendNetlinkMessage(int fd, const void* data, size_t byteCount) {
    ssize_t sentByteCount = TEMP_FAILURE_RETRY(send(fd, data, byteCount, 0));
    return (sentByteCount == (ssize_t)byteCount);
}

static ssize_t recvNetlinkMessage(int fd, char* buf, size_t byteCount) {
    return TEMP_FAILURE_RETRY(recv(fd, buf, byteCount, 0));
}

// Source-compatible with the BSD function.
void freeifaddrs(struct ifaddrs* list) {
    while (list != NULL) {
        struct ifaddrs* addr = list;
        list = list->ifa_next;
        free(addr->ifa_name);
        free(addr->ifa_addr);
        free(addr->ifa_netmask);
        free(addr);
    }
}

// Source-compatible with the BSD function.
int getifaddrs(struct ifaddrs** result) {
    // Simplify cleanup for callers.
    *result = NULL;

    // Create a netlink socket.
    int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }

    // Ask for the address information.
    struct addrReq_struct addrRequest;
    memset(&addrRequest, 0, sizeof(addrRequest));
    addrRequest.netlinkHeader.nlmsg_flags = NLM_F_REQUEST | NLM_F_MATCH;
    addrRequest.netlinkHeader.nlmsg_type = RTM_GETADDR;
    addrRequest.netlinkHeader.nlmsg_len = NLMSG_ALIGN(NLMSG_LENGTH(sizeof(addrRequest)));
    addrRequest.msg.ifa_family = AF_UNSPEC; // All families.
    addrRequest.msg.ifa_index = 0; // All interfaces.
    if (!sendNetlinkMessage(fd, &addrRequest, addrRequest.netlinkHeader.nlmsg_len)) {
        goto err;
    }

    // Read the responses.
    char buf[65536];
    ssize_t bytesRead;
    while ((bytesRead  = recvNetlinkMessage(fd, buf, sizeof(buf))) > 0) {
        struct nlmsghdr* hdr = (struct nlmsghdr*)buf;
        for (; NLMSG_OK(hdr, (size_t)bytesRead); hdr = NLMSG_NEXT(hdr, bytesRead)) {
            switch (hdr->nlmsg_type) {
            case NLMSG_ERROR:
                goto err;
            case RTM_NEWADDR: {
                struct ifaddrmsg* address = (struct ifaddrmsg*)NLMSG_DATA(hdr);
                struct rtattr* rta = IFA_RTA(address);
                size_t ifaPayloadLength = IFA_PAYLOAD(hdr);
                while (RTA_OK(rta, ifaPayloadLength)) {
                    if (rta->rta_type == IFA_LOCAL) {
                        int family = address->ifa_family;
                        if (family == AF_INET || family == AF_INET6) {
                            *result = (struct ifaddrs*)calloc(1, sizeof(struct ifaddrs));
                            if (!setNameAndFlagsByIndex(*result, address->ifa_index)) {
                                goto err;
                            }
                            setAddress(*result, family, RTA_DATA(rta), RTA_PAYLOAD(rta));
                            setNetmask(*result, family, address->ifa_prefixlen);
                        }
                    }
                    rta = RTA_NEXT(rta, ifaPayloadLength);
                }
                break;
            }
            case NLMSG_DONE:
                close(fd);
                return 0;
            }
        }
    }
err:
    close(fd);
    freeifaddrs(*result);
    return -1;
}

#endif
