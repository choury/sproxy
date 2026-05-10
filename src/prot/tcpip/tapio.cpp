#include "tapio.h"
#include "common/common.h"
#include "hook/hook.h"
#include "misc/buffer.h"
#include "misc/net.h"
#include "misc/pcap.h"

#include <cstring>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#ifdef __linux__
#include <linux/if_ether.h>
#else
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP  0x0806
#endif
#include <netinet/ip.h>
#include <netinet/ip6.h>

struct ArpPacket {
    struct arphdr hdr;
    uint8_t ar_sha[ETH_ALEN];
    uint32_t ar_spa;
    uint8_t ar_tha[ETH_ALEN];
    uint32_t ar_tpa;
} __attribute__((packed));

static bool ProcessArpPacket(const ArpPacket* arp, size_t len, Buffer& reply) {
    static const uint32_t vpn_netmask = ntohl(inet_addr(VPNMASK));
    static const uint32_t vpn_network = ntohl(inet_addr(VPNADDR)) & vpn_netmask;

    if (len < sizeof(ArpPacket)) return false;

    if (ntohs(arp->hdr.ar_hrd) != ARPHRD_ETHER ||
        ntohs(arp->hdr.ar_pro) != ETH_P_IP) return false;
    if (arp->hdr.ar_hln != ETH_ALEN || arp->hdr.ar_pln != 4) return false;
    if (ntohs(arp->hdr.ar_op) != ARPOP_REQUEST) return false;

    // 回应 198.18.0.0/15 范围内的所有 ARP 请求
    if ((ntohl(arp->ar_tpa) & vpn_netmask) != vpn_network) return false;

    size_t reply_len = sizeof(ArpPacket);
    reply.reserve(-(int)reply_len);
    auto* reply_arp = reinterpret_cast<ArpPacket*>(reply.mutable_data());
    reply_arp->hdr.ar_hrd = htons(ARPHRD_ETHER);
    reply_arp->hdr.ar_pro = htons(ETH_P_IP);
    reply_arp->hdr.ar_hln = ETH_ALEN;
    reply_arp->hdr.ar_pln = 4;
    reply_arp->hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(reply_arp->ar_sha, VPNMAC, ETH_ALEN);
    reply_arp->ar_spa = arp->ar_tpa;
    memcpy(reply_arp->ar_tha, arp->ar_sha, ETH_ALEN);
    reply_arp->ar_tpa = arp->ar_spa;

    reply.truncate(reply_len);
    return true;
}


static constexpr uint8_t BROADCAST_MAC[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

void TapRWer::SendFrame(const uint8_t* dstMac, uint16_t proto, Buffer&& bb, const GsoInfo& gso, int ip_hdr_len) {
    // 添加 Ethernet 头
    bb.reserve(-(int)ETH_HDR_LEN);
    auto* eth = static_cast<ethhdr*>(bb.mutable_data());
    memcpy(eth->h_dest, dstMac, ETH_ALEN);
    memcpy(eth->h_source, VPNMAC, ETH_ALEN);
    eth->h_proto = htons(proto);
    pcap_write(pcap, bb.data(), bb.len);

    // 添加 virtio 头
#if __linux__
    if (enable_offload) {
        bb.reserve(-(int)sizeof(virtio_net_hdr_v1));
        auto *hdr = (virtio_net_hdr_v1*)bb.mutable_data();
        memset(hdr, 0, sizeof(virtio_net_hdr_v1));
        hdr->flags = ip_hdr_len ? VIRTIO_NET_HDR_F_NEEDS_CSUM : 0;
        hdr->csum_start = ETH_HDR_LEN + ip_hdr_len;
        hdr->csum_offset = gso.csum_offset;
        hdr->hdr_len = hdr->csum_start + gso.l4_hdrlen;
        hdr->gso_size = gso.gso_size;
        hdr->gso_type = gso.gso_type;
    }
#else
    (void)gso;
    (void)ip_hdr_len;
#endif
    WriteToDevice(std::move(bb));
}

void TapRWer::learnMac(const ethhdr* eth, const char* ip_data, bool is_ipv6) {
    if (is_ipv6) {
        const ip6_hdr* ip6 = reinterpret_cast<const ip6_hdr*>(ip_data);
        std::array<uint8_t, 16> key;
        memcpy(key.data(), &ip6->ip6_src, 16);
        memcpy(macCache6[key].data(), eth->h_source, ETH_ALEN);
    } else {
#ifdef __linux__
        const iphdr* ip4 = reinterpret_cast<const iphdr*>(ip_data);
        uint32_t src = ip4->saddr;
#else
        const struct ip* ip4 = reinterpret_cast<const struct ip*>(ip_data);
        uint32_t src = ip4->ip_src.s_addr;
#endif
        memcpy(macCache4[src].data(), eth->h_source, ETH_ALEN);
    }
}

TapRWer::TapRWer(int fd, bool enable_offload, std::shared_ptr<IRWerCallback> cb)
    : TunRWer(fd, enable_offload, std::move(cb))
{
}

void TapRWer::ProcessPacket(Buffer&& bb) {
#if __linux__
    if((size_t)bb.len < sizeof(virtio_net_hdr_v1)) {
        return;
    }
    if(enable_offload) {
        auto hdr = (const virtio_net_hdr_v1*)bb.data();
        if(hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
            LOGD(DVPN, "tap gso type: %d, gso size: %d, num: %d\n",
                 hdr->gso_type, hdr->gso_size, hdr->num_buffers);
        }
        bb.reserve(sizeof(virtio_net_hdr_v1));
    }
#endif
    pcap_write(pcap, bb.data(), bb.len);

    const ethhdr* eth = static_cast<const ethhdr*>(bb.data());
    uint16_t proto = ntohs(eth->h_proto);

    // Strip Ethernet header
    bb.reserve(ETH_HDR_LEN);
    if (proto == ETH_P_IP) {
        learnMac(eth, static_cast<const char*>(bb.data()), false);
        ProcessIpPacket(std::move(bb));
    } else if (proto == ETH_P_IPV6) {
        learnMac(eth, static_cast<const char*>(bb.data()), true);
        ProcessIpPacket(std::move(bb));
    } else if (proto == ETH_P_ARP) {
        const ArpPacket* arp = reinterpret_cast<const ArpPacket*>(bb.data());
        LOGD(DVPN, "<arp> request who-has %s tell %s\n",
            std::string(inet_ntoa(in_addr{arp->ar_tpa})).c_str(), std::string(inet_ntoa(in_addr{arp->ar_spa})).c_str());
        Buffer reply(nullptr);
        if(!ProcessArpPacket(arp, bb.len, reply)) {
            return;
        }
        LOGD(DVPN, "<arp> reply %s is-at %02x:%02x:%02x:%02x:%02x:%02x\n",
            inet_ntoa(in_addr{arp->ar_tpa}),
            VPNMAC[0], VPNMAC[1], VPNMAC[2], VPNMAC[3], VPNMAC[4], VPNMAC[5]);
        SendFrame(arp->ar_sha, ETH_P_ARP, std::move(reply), {}, 0);
    }
}

void TapRWer::SendPkg(std::shared_ptr<Ip> pac, Buffer&& bb, const GsoInfo& gso) {
    // 构建 L4 + IP 头
    pac->build_packet(bb);
    HOOK_BPF(this, pac, std::span<const std::byte>((const std::byte*)bb.data(), bb.len));
    debugString(pac, bb.len - pac->gethdrlen(), true);

    // 查找目标 MAC
    const uint8_t* dstMac = BROADCAST_MAC;
    auto dst = pac->getdst();
    if (dst.ss_family == AF_INET) {
        auto* addr = reinterpret_cast<const sockaddr_in*>(&dst);
        uint32_t dstIp = addr->sin_addr.s_addr;
        auto it = macCache4.find(dstIp);
        if (it != macCache4.end()) {
            dstMac = it->second.data();
        }
    } else if (dst.ss_family == AF_INET6) {
        auto* addr = reinterpret_cast<const sockaddr_in6*>(&dst);
        std::array<uint8_t, 16> key;
        memcpy(key.data(), &addr->sin6_addr, 16);
        auto it = macCache6.find(key);
        if (it != macCache6.end()) {
            dstMac = it->second.data();
        }
    }

    uint16_t proto = (dst.ss_family == AF_INET6) ? ETH_P_IPV6 : ETH_P_IP;
    SendFrame(dstMac, proto, std::move(bb), gso, pac->gethdrlen() - gso.l4_hdrlen);
}
