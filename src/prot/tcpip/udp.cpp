#include "udp.h"
#include "dhcp.h"
#include "misc/net.h"

static void makeUdp(std::shared_ptr<UdpStatus> status, std::shared_ptr<Ip> pac, Buffer& bb) {
    pac->build_packet(bb);
#if __linux__
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
#else
    (void)status;
#endif
}

static void handleDhcp(std::shared_ptr<UdpStatus> status, Buffer&& bb) {
    const DhcpHeader* req = (const DhcpHeader*)bb.data();
    if(req->op != 1 || req->htype != 1 || req->hlen != 6) return;
    uint8_t* ops = (uint8_t*)&req->options[0];
    uint8_t type = 0;
    while(ops - (uint8_t*)req < (int)bb.len) {
        const DhcpOption* option = (DhcpOption*)ops;
        switch(option->code) {
        case DHCP_MSG_TYPE:
            type = option->data[0];
            break;
        case DHCP_END:
            goto reply;
        }
        ops += option->len + 2;
    }
reply:
    LOGD(DVPN, "get dhcp request: %d\n", type);
    Buffer rbb(512);
    DhcpHeader* reply = (DhcpHeader*)bb.mutable_data();
    memcpy(reply, req, sizeof(DhcpHeader));
    reply->op = 2;
    reply->yiaddr = inet_addr(VPNADDR);
    ops = &reply->options[0];

    sockaddr_storage dst;
    if(type == DHCP_TYPE_DISCOVER){
        storage_aton("255.255.255.255", DHCP_CLIENT_PORT, &dst);
        DhcpOption* option = (DhcpOption*)ops;
        option->code = DHCP_MSG_TYPE;
        option->len = 1;
        option->data[0] = DHCP_TYPE_OFFER;
        ops += option->len + 2;
    }else if(type == DHCP_TYPE_REQUEST) {
        storage_aton(VPNADDR, DHCP_CLIENT_PORT, &dst);
        DhcpOption* option = (DhcpOption*)ops;
        option->code = DHCP_MSG_TYPE;
        option->len = 1;
        option->data[0] = DHCP_TYPE_ACK;
        ops += option->len + 2;
    }else {
        LOG("ignore dhcp type: %d\n", type);
        return;
    }
    DhcpOption* option = (DhcpOption*)ops;
    option->code = DHCP_LEASE_TIME;
    option->len = 4;
    set32(option->data, 86400);
    ops += option->len + 2;

    option = (DhcpOption*)ops;
    option->code = DHCP_SUBNET_MASK;
    option->len = 4;
    *(uint32_t*)option->data = inet_addr(VPNMASK);
    ops += option->len + 2;

    option = (DhcpOption*)ops;
    option->code = DHCP_NAMESERVER;
    option->len = 4;
    *(uint32_t*)option->data = inet_addr("198.18.0.2");
    ops += option->len + 2;

    option = (DhcpOption*)ops;
    option->code = DHCP_SERVER;
    option->len = 4;
    *(uint32_t*)option->data = inet_addr(VPNEND);
    ops += option->len + 2;

    *ops++ = DHCP_END;
    *ops = 0;

    bb.truncate((char*)ops - (char*)reply);

    sockaddr_storage src;
    storage_aton(VPNEND, DHCP_SERVER_PORT, &src);
    auto pac = MakeIp(IPPROTO_UDP, &src, &dst);
    makeUdp(status, pac, bb);
    status->sendCB(pac, std::move(bb));
}

void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb) {
    uint16_t dport = pac->getdport();
    if(status->aged_job == nullptr) {
        if(dport == 53){
            status->flags |= UDP_IS_DNS;
        }
        if(dport == DHCP_SERVER_PORT) {
            bb.reserve(pac->gethdrlen());
            handleDhcp(status, std::move(bb));
            return;
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
    makeUdp(status, pac, bb);
    status->sendCB(pac, std::move(bb));
    status->ack_job = updatejob_with_name(std::move(status->ack_job),
                                          [ackCB = status->ackCB, rpac]{ackCB(rpac);},
                                          "udp_ack_job", 0);
}
