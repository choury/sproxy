#include "icmp.h"
#include "misc/buffer.h"
#include "misc/net.h"

#include <arpa/inet.h>
#include <cstring>

void IcmpProc(std::shared_ptr<IcmpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb) {
    // Handle NDP Neighbor Solicitation - reply with NA directly
    if(pac->gettype() == IPPROTO_ICMPV6 && pac->icmp6->gettype() == ND_NEIGHBOR_SOLICIT) {
        static const in6_addr vpn_addr6 = []{
            in6_addr addr{};
            inet_pton(AF_INET6, VPNADDR6, &addr);
            return addr;
        }();
        static const uint32_t vpn_netmask = ntohl(inet_addr(VPNMASK));
        static const uint32_t vpn_network = ntohl(inet_addr(VPNADDR)) & vpn_netmask;

        in6_addr target = pac->icmp6->gettarget();
        // 只回应 VPN 网段内的 NS
        if(memcmp(&target, &vpn_addr6, 12) != 0) return;
        uint32_t tpa;
        memcpy(&tpa, &target.s6_addr[12], 4);
        if((ntohl(tpa) & vpn_netmask) != vpn_network) return;
        sockaddr_storage gateway_ss{};
        auto* gw6 = reinterpret_cast<sockaddr_in6*>(&gateway_ss);
        gw6->sin6_family = AF_INET6;
        gw6->sin6_addr = target;

        auto na_pac = MakeIp(IPPROTO_ICMPV6, &gateway_ss, &status->src);
        na_pac->setttl(255)
            ->icmp6
            ->settype(ND_NEIGHBOR_ADVERT)
            ->setndflags(ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE)
            ->settarget(target)
            ->settlla(VPNMAC);
        Buffer reply(nullptr);
        GsoInfo gso;
        gso.l4_hdrlen = sizeof(icmp6_hdr);
        gso.csum_offset = 2;
        status->sendCB(na_pac, std::move(reply), gso);
        return;
    }

    if(status->id == 0) {
        status->reqCB(pac);
    }
    if(pac->getdst().ss_family == AF_INET) {
        assert(pac->icmp->gettype() == ICMP_ECHO);
        status->id = pac->icmp->getid();
        status->seq = pac->icmp->getseq();
    }else{
        assert(pac->icmp6->gettype() == ICMP6_ECHO_REQUEST);
        status->id = pac->icmp6->getid();
        status->seq = pac->icmp6->getseq();
    }
    bb.reserve(pac->gethdrlen());
    status->aged_job = updatejob_with_name(std::move(status->aged_job),
                                           [errCB = status->errCB, pac]{errCB(pac, CONNECT_AGED);},
                                           "icmp_aged_job", 30000);
    if(bb.len > 0) {
        status->dataCB(pac, std::move(bb));
    }
}


void SendData(std::shared_ptr<IcmpStatus> status, Buffer&& bb) {
    auto rpac = MakeIp(status->packet_hdr.data(), status->packet_hdr.size());
    if(bb.len == 0){
        status->aged_job = updatejob_with_name(std::move(status->aged_job),
                                               [errCB = status->errCB, rpac]{errCB(rpac, CONNECT_AGED);},
                                               "icmp_aged_job", 0);
        return;
    } else {
        status->aged_job = updatejob_with_name(std::move(status->aged_job),
                                               [errCB = status->errCB, rpac]{errCB(rpac, CONNECT_AGED);},
                                               "icmp_aged_job", 30000);
    }

    std::shared_ptr<Ip> pac;
    if(status->src.ss_family == AF_INET){
        pac = MakeIp(IPPROTO_ICMP, &status->dst, &status->src);
        pac->icmp
            ->settype(ICMP_ECHOREPLY)
            ->setcode(0)
            ->setid(status->id)
            ->setseq(status->seq);
    }else{
        pac = MakeIp(IPPROTO_ICMPV6, &status->dst, &status->src);
        pac->icmp6
            ->settype(ICMP6_ECHO_REPLY)
            ->setcode(0)
            ->setid(status->id)
            ->setseq(status->seq);
    }
    // 填充 GSO 参数
    GsoInfo gso;
    gso.l4_hdrlen = status->src.ss_family == AF_INET ? sizeof(icmphdr) : sizeof(icmp6_hdr);
    gso.csum_offset = 2;
    status->sendCB(pac, std::move(bb), gso);
    status->ack_job = updatejob_with_name(std::move(status->ack_job),
                                          [ackCB = status->ackCB, rpac]{ackCB(rpac);},
                                          "icmp_ack_job", 0);
}
