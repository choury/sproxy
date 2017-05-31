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
    const char* server;
};

int vpn_start(const struct VpnConfig* vpn);
void vpn_stop();
#endif

#ifdef  __cplusplus
}
#endif
