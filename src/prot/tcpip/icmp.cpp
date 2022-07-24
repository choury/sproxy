#include "icmp.h"


void IcmpHE::DefaultProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    std::shared_ptr<IcmpStatus> status = std::static_pointer_cast<IcmpStatus>(status_);
    if(status->id == 0) {
        ReqProc(pac);
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
    size_t datalen = len - pac->gethdrlen();
    status->aged_job =status->jobHandler.updatejob_with_name(status->aged_job, [this, pac]{
        ErrProc(pac, CONNECT_AGED);
    }, "icmp_aged_job", 30000);
    if(datalen > 0) {
        DataProc(pac, packet + pac->gethdrlen(), datalen);
    }
}


void IcmpHE::SendData(std::shared_ptr<IpStatus> status_, Buffer&& bb) {
    std::shared_ptr<IcmpStatus> status = std::static_pointer_cast<IcmpStatus>(status_);
    auto rpac = MakeIp(status->packet_hdr->data(), status->packet_hdr_len);
    if(bb.len == 0){
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, rpac]{
            ErrProc(rpac, CONNECT_AGED);
        }, "icmp_aged_job", 0);
        return;
    } else {
        status->aged_job = status->jobHandler.updatejob_with_name(status->aged_job, [this, rpac]{
            ErrProc(rpac, CONNECT_AGED);
        }, "icmp_aged_job", 30000);
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
    sendPkg(pac, bb.data(), bb.len);
    status->ack_job = status->jobHandler.updatejob_with_name(status->ack_job, [this, rpac]{
        AckProc(rpac);
    }, "icmp_ack_job", 0);
}
