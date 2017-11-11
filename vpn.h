#ifndef VPN_H__
#define VPN_H__

#include "common.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define VPN_MTU  (BUF_LEN+120)

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFF
#endif

struct VpnConfig{
    int fd;
    int ignore_cert_error;
    int disable_ipv6;
    char server[DOMAINLIMIT];
    char secret[DOMAINLIMIT];
};

typedef int (Vpn_start)(const struct VpnConfig* vpn);
typedef void (Vpn_stop)();
typedef void (Vpn_reset)();
typedef void (Vpn_reload)();

Vpn_start vpn_start;
Vpn_stop vpn_stop;
Vpn_reset vpn_reset;
Vpn_reload vpn_reload;
#endif

#ifdef  __cplusplus
}
#endif
