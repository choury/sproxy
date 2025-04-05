#ifndef IP_H__
#define IP_H__

#include "common/common.h"
#include "ip_pack.h"
#include "misc/buffer.h"
#include <unistd.h>
#include <functional>

struct IpStatus;
void Unreach(std::shared_ptr<IpStatus> status, uint8_t code);
forceinline  ssize_t Cap(std::shared_ptr<IpStatus>) {
    return MAX_BUF_LEN;
}

struct IpStatus{
    std::function<void(std::shared_ptr<const Ip>)> reqCB;
    std::function<void(std::shared_ptr<const Ip>)> ackCB;
    std::function<size_t(std::shared_ptr<const Ip>, Buffer&&)> dataCB;
    std::function<void(std::shared_ptr<const Ip>, uint32_t)> errCB;
    std::function<void(std::shared_ptr<const Ip>, const void*, size_t)> sendCB;

    std::function<void(std::shared_ptr<const Ip>, Buffer&&)> PkgProc;
    std::function<void(Buffer&&)> SendPkg;
#define IP_PORT_UNREACH 1
#define IP_ADDR_UNREACH 2
    std::function<void(uint8_t code)> UnReach;
    std::function<ssize_t()> Cap;
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    Block*      packet_hdr;
    uint16_t    packet_hdr_len;
#define  TUN_GSO_OFFLOAD 1
#define  TUN_SEND_EOF    2
    uint32_t    flags = 0;
};

#endif
