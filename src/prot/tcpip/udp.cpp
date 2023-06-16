#include "udp.h"


void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    if(status->aged_job == nullptr) {
        status->isDns = pac->getdport() == 53;
        status->reqCB(pac);
        status->aged_job = status->jobHandler.addjob_with_name(std::bind(status->errCB, pac, CONNECT_AGED),
                                                               "udp_aged_job", status->isDns?5000:30000, 0);
    }else {
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job,
                                                                  std::bind(status->errCB, pac, CONNECT_AGED),
                                                                  "udp_aged_job", status->isDns?5000:120000);
    }
    size_t datalen = len - pac->gethdrlen();
    status->readlen += datalen;
    if(datalen > 0) {
        status->dataCB(pac, packet + pac->gethdrlen(), datalen);
    }
}


void SendData(std::shared_ptr<UdpStatus> status, Buffer&& bb) {
    auto rpac = MakeIp(IPPROTO_UDP, &status->src, &status->dst);
    if(bb.len == 0){
        status->aged_job =  status->jobHandler.updatejob_with_name(status->aged_job,
                                                                   std::bind(status->errCB, rpac, CONNECT_AGED),
                                                                   "udp_aged_job", 0);
        return;
    } else {
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job,
                                                                  std::bind(status->errCB, rpac, CONNECT_AGED),
                                                                  "udp_aged_job", status->isDns?5000:120000);
    }

    auto pac = MakeIp(IPPROTO_UDP, &status->dst, &status->src);
    pac->build_packet(bb);
    status->sendCB(pac, bb.data(), bb.len);
    status->ack_job = status->jobHandler.updatejob_with_name(status->ack_job,
                                                             std::bind(status->ackCB, rpac),
                                                             "udp_ack_job", 0);
}
