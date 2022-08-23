#include "udp.h"


void UdpHE::DefaultProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    std::shared_ptr<UdpStatus> status = std::static_pointer_cast<UdpStatus>(status_);
    if(status->aged_job == nullptr) {
        ReqProc(pac);
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, pac]{
            ErrProc(pac, CONNECT_AGED);
        }, "udp_aged_job", 30000);
    }else {
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, pac]{
            ErrProc(pac, CONNECT_AGED);
        }, "udp_aged_job", 120000);
    }
    size_t datalen = len - pac->gethdrlen();
    status->readlen += datalen;
    if(datalen > 0) {
        DataProc(pac, packet + pac->gethdrlen(), datalen);
    }
}


void UdpHE::SendData(std::shared_ptr<IpStatus> status_, Buffer&& bb) {
    std::shared_ptr<UdpStatus> status = std::static_pointer_cast<UdpStatus>(status_);
    auto rpac = MakeIp(IPPROTO_UDP, &status->src, &status->dst);
    if(bb.len == 0){
        status->aged_job =  status->jobHandler.updatejob_with_name(status->aged_job, [this, rpac]{
            ErrProc(rpac, CONNECT_AGED);
        }, "udp_aged_job", 0);
        return;
    } else {
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, rpac] {
            ErrProc(rpac, CONNECT_AGED);
        }, "udp_aged_job", 120000);
    }

    auto pac = MakeIp(IPPROTO_UDP, &status->dst, &status->src);
    pac->build_packet(bb);
    sendPkg(pac, bb.data(), bb.len);
    status->ack_job = status->jobHandler.updatejob_with_name(status->ack_job, [this, rpac]{
        AckProc(rpac);
    }, "udp_ack_job", 0);
}
