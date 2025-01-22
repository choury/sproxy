#ifndef DHCP_H__
#define DHCP_H__


#include <stdint.h>

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67


#define DHCP_SUBNET_MASK  1
#define DHCP_ROUTER       3
#define DHCP_NAMESERVER   5
#define DHCP_LEASE_TIME   51
#define DHCP_MSG_TYPE     53
#define DHCP_SERVER       54
#define DHCP_END          255

#define DHCP_TYPE_DISCOVER 1
#define DHCP_TYPE_OFFER    2
#define DHCP_TYPE_REQUEST  3
#define DHCP_TYPE_DECLINE  4
#define DHCP_TYPE_ACK      5
#define DHCP_TYPE_NAK      6
#define DHCP_TYPE_RELEASE  7
struct DhcpOption {
    uint8_t code;
    uint8_t len;
    uint8_t data[0];
} __attribute__((packed));


#define DHCP_MAGIC 0x63825363

struct DhcpHeader {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic;
    uint8_t options[0];
} __attribute__((packed));

#endif
