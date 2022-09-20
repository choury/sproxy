#ifndef VPN_H__
#define VPN_H__

#include "common/common.h"
#include "misc/config.h"

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFF
#endif

int vpn_start(int fd);
void vpn_stop();

#ifdef  __cplusplus
}
#endif

#endif
