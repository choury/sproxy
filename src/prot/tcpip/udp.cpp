#include "udp.h"


void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb) {
    if(status->aged_job == nullptr) {
        if(pac->getdport() == 53){
            status->flags |= UDP_IS_DNS;
        }
        status->reqCB(pac);
        status->aged_job = addjob_with_name([errCB = status->errCB, pac]{errCB(pac, CONNECT_AGED);},
                                            "udp_aged_job", (status->flags & UDP_IS_DNS)?5000:30000, 0);
    }else {
        status->aged_job = updatejob_with_name(std::move(status->aged_job),
                                               [errCB = status->errCB, pac]{errCB(pac, CONNECT_AGED);},
                                               "udp_aged_job", (status->flags & UDP_IS_DNS)?5000:120000);
    }
    bb.reserve(pac->gethdrlen());
    status->readlen += bb.len;
    if(bb.len > 0) {
        status->dataCB(pac, std::move(bb));
    }
}


void SendData(std::shared_ptr<UdpStatus> status, Buffer&& bb) {
    auto rpac = MakeIp(IPPROTO_UDP, &status->src, &status->dst);
    if(bb.len == 0){
        status->aged_job =  updatejob_with_name(std::move(status->aged_job),
                                                [errCB = status->errCB, rpac]{errCB(rpac, CONNECT_AGED);},
                                                "udp_aged_job", 0);
        return;
    } else {
        status->aged_job = updatejob_with_name(std::move(status->aged_job),
                                               [errCB = status->errCB, rpac]{errCB(rpac, CONNECT_AGED);},
                                               "udp_aged_job", (status->flags & UDP_IS_DNS)?5000:120000);
    }

    auto pac = MakeIp(IPPROTO_UDP, &status->dst, &status->src);
    pac->build_packet(bb);
    if(status->flags & TUN_GSO_OFFLOAD) {
        bb.reserve(-(int)sizeof(virtio_net_hdr_v1));
        auto hdr = (virtio_net_hdr_v1*)bb.mutable_data();
        hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        hdr->gso_type = VIRTIO_NET_HDR_GSO_NONE;
        hdr->hdr_len = pac->gethdrlen();
        hdr->gso_size = 0;
        hdr->csum_start = hdr->hdr_len - sizeof(udphdr);
        hdr->csum_offset = 6;
    }
    status->sendCB(pac, bb.data(), bb.len);
    status->ack_job = updatejob_with_name(std::move(status->ack_job),
                                          [ackCB = status->ackCB, rpac]{ackCB(rpac);},
                                          "udp_ack_job", 0);
}
