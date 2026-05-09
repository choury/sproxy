#include "ipbase.h"
#include "tcp.h"
#include "misc/buffer.h"
#include "misc/net.h"

void Unreach(std::shared_ptr<IpStatus> status, uint8_t code) {
    std::shared_ptr<Ip> pac;
    if (status->src.ss_family == AF_INET) {
        LOGD(DVPN, "write icmp unreach packet\n");
        pac = MakeIp(IPPROTO_ICMP, &status->dst, &status->src);
        pac->icmp->settype(ICMP_UNREACH);
        switch (code) {
        case IP_ADDR_UNREACH:
            pac->icmp->setcode(ICMP_UNREACH_HOST);
            break;
        case IP_PORT_UNREACH:
            pac->icmp->setcode(ICMP_UNREACH_PORT);
            break;
        }
    } else {
        LOGD(DVPN, "write icmp6 unreach packet\n");
        pac = MakeIp(IPPROTO_ICMPV6, &status->dst, &status->src);
        pac->icmp6->settype(ICMP6_DST_UNREACH);
        switch (code) {
        case IP_ADDR_UNREACH:
            pac->icmp6->setcode(ICMP6_DST_UNREACH_ADDR);
            break;
        case IP_PORT_UNREACH:
            pac->icmp6->setcode(ICMP6_DST_UNREACH_NOPORT);
            break;
        }
    }
    Buffer bb{status->packet_hdr.data(), status->packet_hdr.size()};
    status->packet_hdr.clear();
    // 填充 GSO 参数
    GsoInfo gso;
    gso.l4_hdrlen = status->src.ss_family == AF_INET ? sizeof(icmphdr) : sizeof(icmp6_hdr);
    gso.csum_offset = 2;
    status->sendCB(pac, std::move(bb), gso);
}

void UpdateTcpMss(const std::shared_ptr<IpStatus>& status, uint16_t mss) {
    if(!status || status->protocol != Protocol::TCP) {
        return;
    }
    auto tstatus = std::static_pointer_cast<TcpStatus>(status);
    if(mss == 0 || mss >= tstatus->mss) {
        return;
    }
    LOGD(DVPN, "tcp mss update %u -> %u\n", tstatus->mss, mss);
    tstatus->mss = mss;
}
