#ifndef UDP_H__
#define UDP_H__

#include "ipbase.h"

struct UdpStatus;

void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb);
void SendData(std::shared_ptr<UdpStatus> status, Buffer&& bb);


struct UdpStatus: public IpStatus{
    size_t readlen  = 0;
    bool   isDns = false;
    Job   aged_job = nullptr;
    Job   ack_job = nullptr;
};

#endif
