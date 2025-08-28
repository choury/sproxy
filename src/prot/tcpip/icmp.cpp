#include "icmp.h"
#include "misc/buffer.h"
#include "misc/net.h"

void IcmpProc(std::shared_ptr<IcmpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb) {
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
    pac->build_packet(bb);
#if __linux__
    if(status->flags & TUN_GSO_OFFLOAD) {
        bb.reserve(-(int)sizeof(virtio_net_hdr_v1));
        auto hdr = (virtio_net_hdr_v1*)bb.mutable_data();
        hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
        hdr->hdr_len = pac->gethdrlen();
        hdr->gso_size = 0;
        if(status->src.ss_family == AF_INET){
            hdr->csum_start = hdr->hdr_len - sizeof(icmphdr);
        }else{
            hdr->csum_start = hdr->hdr_len - sizeof(icmp6_hdr);
        }
        hdr->csum_offset = 2;
    }
#endif
    status->sendCB(pac, std::move(bb));
    status->ack_job = updatejob_with_name(std::move(status->ack_job),
                                          [ackCB = status->ackCB, rpac]{ackCB(rpac);},
                                          "icmp_ack_job", 0);
}
