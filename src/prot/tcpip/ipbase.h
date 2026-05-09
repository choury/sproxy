#ifndef IP_H__
#define IP_H__

#include "common/common.h"
#include "ip_pack.h"
#include <unistd.h>
#include <string>
#include <functional>

class Buffer;
class Block;
struct IpStatus;
void Unreach(std::shared_ptr<IpStatus> status, uint8_t code);
void UpdateTcpMss(const std::shared_ptr<IpStatus>& status, uint16_t mss);
forceinline  ssize_t Cap(std::shared_ptr<IpStatus>) {
    return MAX_BUF_LEN;
}

// GSO 协议参数，由 L4 协议处理器填充，输出层直接使用
struct GsoInfo {
    uint16_t l4_hdrlen = 0;   // L4 头长度
    uint16_t csum_offset = 0; // 校验和在 L4 头中的偏移
    uint16_t gso_size = 0;    // GSO 分段大小，0 = 不分段
    uint8_t  gso_type = 0;    // GSO 类型（VIRTIO_NET_HDR_GSO_*）
};

struct IpStatus{
    std::function<void(std::shared_ptr<const Ip>)> reqCB;
    std::function<void(std::shared_ptr<const Ip>)> ackCB;
    std::function<size_t(std::shared_ptr<const Ip>, Buffer&&)> dataCB;
    std::function<void(std::shared_ptr<const Ip>, uint32_t)> errCB;
    std::function<void(std::shared_ptr<Ip>, Buffer&&, const GsoInfo&)> sendCB;

    std::function<void(std::shared_ptr<const Ip>, Buffer&&)> PkgProc;
    std::function<void(Buffer&&)> SendPkg;
#define IP_PORT_UNREACH 1
#define IP_ADDR_UNREACH 2
    std::function<void(uint8_t code)> UnReach;
    std::function<ssize_t()> Cap;
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    std::string      packet_hdr;
#define  TUN_GSO_OFFLOAD 1
#define  TUN_SEND_EOF    2
    uint32_t    flags = 0;
};

#endif
