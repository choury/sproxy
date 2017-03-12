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

int vpn_start(int fd);
#endif

#ifdef  __cplusplus
}
#endif
