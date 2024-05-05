#include "ipbase.h"

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
    Buffer bb{std::move(*status->packet_hdr), status->packet_hdr_len};
    delete status->packet_hdr;
    status->packet_hdr = nullptr;
    pac->build_packet(bb);
    status->sendCB(pac, bb.data(), bb.len);
}
