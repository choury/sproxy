#include "udp.h"


void UdpHE::DefaultProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    std::shared_ptr<UdpStatus> status = std::static_pointer_cast<UdpStatus>(status_);
    if(status->aged_job == nullptr) {
        ReqProc(pac);
    }
    size_t datalen = len - pac->gethdrlen();
    status->readlen += datalen;
    status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, pac]{
        ErrProc(pac, CONNECT_AGED);
    }, "udp_aged_job", 300000);
    DataProc(pac, packet + pac->gethdrlen(), datalen);
}


void UdpHE::SendData(std::shared_ptr<IpStatus> status_, Buffer&& bb) {
    std::shared_ptr<UdpStatus> status = std::static_pointer_cast<UdpStatus>(status_);
    auto rpac = MakeIp(IPPROTO_UDP, &status->src, &status->dst);
    if(bb.len == 0){
        ErrProc(rpac, NOERROR);
        return;
    }
    auto pac = MakeIp(IPPROTO_UDP, &status->dst, &status->src);
    status->aged_job =  status->jobHandler.updatejob_with_name(status->aged_job, [this, rpac]{
        ErrProc(rpac, CONNECT_AGED);
    }, "udp_aged_job", 300000);
    sendPkg(pac, std::move(bb));
}
