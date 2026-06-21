#include "udp.h"
#include "dhcp.h"
#include "misc/buffer.h"
#include "misc/config.h"
#include "misc/net.h"

static void handleDhcp(std::shared_ptr<UdpStatus> status, Buffer&& bb) {
    static const uint32_t vpnaddr = inet_addr(VPNADDR);
    static const uint32_t vpnend = inet_addr(VPNEND);
    const DhcpHeader* req = (const DhcpHeader*)bb.data();
    if(bb.len < (int)sizeof(DhcpHeader)) return;
    if(req->op != 1 || req->htype != 1 || req->hlen != 6) return;
    uint8_t* ops = (uint8_t*)&req->options[0];
    uint8_t type = 0;
    uint32_t server_id = 0;
    while(ops - (uint8_t*)req < (int)bb.len) {
        const DhcpOption* option = (DhcpOption*)ops;
        if(option->code == DHCP_PAD) {
            ops++;
            continue;
        }
        if(option->code == DHCP_END) {
            goto reply;
        }
        // 检查 len + data 是否越界
        if(ops - (uint8_t*)req + 2 + option->len > (int)bb.len) {
            return;
        }
        switch(option->code) {
        case DHCP_MSG_TYPE:
            type = option->data[0];
            break;
        case DHCP_SERVER:
            if(option->len == 4) {
                memcpy(&server_id, option->data, 4);
            }
            break;
        }
        ops += option->len + 2;
    }
reply:
    LOGD(DVPN, "get dhcp request: %d\n", type);
    Buffer rbb(512);
    DhcpHeader* reply = (DhcpHeader*)bb.mutable_data();
    memcpy(reply, req, sizeof(DhcpHeader));
    reply->op = 2;
    reply->yiaddr = vpnaddr;
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
        // SELECTING 阶段的 REQUEST 必须带 server identifier,指明客户端选了哪台 DHCP 服务器。
        // 选的不是我们就不响应,避免和已有 DHCP 服务器(如 dnsmasq)抢答 ACK。
        // server_id 为 0 表示客户端没带这个 option(RENEWING/REBINDING/INIT-REBOOT 续约),继续正常 ACK。
        if(server_id != 0 && server_id != vpnend) {
            LOGD(DVPN, "ignore dhcp request: client selected another server\n");
            return;
        }
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

    //本机地址不能被设置为网关地址，而且因为整个网段都会做arp应答，所以任意选一个就行
    option = (DhcpOption*)ops;
    option->code = DHCP_ROUTER;
    option->len = 4;
    *(uint32_t*)option->data = inet_addr("198.18.0.2");
    ops += option->len + 2;

    option = (DhcpOption*)ops;
    option->code = DHCP_NAMESERVER;
    option->len = 4;
    *(uint32_t*)option->data = vpnaddr;
    ops += option->len + 2;

    option = (DhcpOption*)ops;
    option->code = DHCP_SERVER;
    option->len = 4;
    *(uint32_t*)option->data = vpnend;
    ops += option->len + 2;

    *ops++ = DHCP_END;
    *ops = 0;

    bb.truncate((char*)ops - (char*)reply);

    sockaddr_storage src;
    storage_aton(VPNEND, DHCP_SERVER_PORT, &src);
    auto pac = MakeIp(IPPROTO_UDP, &src, &dst);
    // 填充 GSO 参数
    GsoInfo gso;
    gso.l4_hdrlen = sizeof(udphdr);
    gso.csum_offset = 6;
    status->sendCB(pac, std::move(bb), gso);
}

void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb) {
    uint16_t dport = pac->getdport();
    if(status->aged_job == nullptr) {
        if(dport == 53){
            status->flags |= UDP_IS_DNS;
        }
        if(dport == DHCP_SERVER_PORT) {
            if(opt.tap_fd < 0) return;
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
    status->rx_len += bb.len;
    status->rx_packets++;
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

    status->tx_len += bb.len;
    status->tx_packets++;
    auto pac = MakeIp(IPPROTO_UDP, &status->dst, &status->src);
    // 填充 GSO 参数
    GsoInfo gso;
    gso.l4_hdrlen = sizeof(udphdr);
    gso.csum_offset = 6;
    status->sendCB(pac, std::move(bb), gso);
    status->ack_job = updatejob_with_name(std::move(status->ack_job),
                                          [ackCB = status->ackCB, rpac]{ackCB(rpac);},
                                          "udp_ack_job", 0);
}
