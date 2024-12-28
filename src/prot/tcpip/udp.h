#ifndef UDP_H__
#define UDP_H__

#include "ipbase.h"

struct UdpStatus;

void UdpProc(std::shared_ptr<UdpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb);
void SendData(std::shared_ptr<UdpStatus> status, Buffer&& bb);


struct UdpStatus: public IpStatus{
//use for flags from IpStatus
#define UDP_IS_DNS 0x100
    size_t readlen  = 0;
    Job   aged_job = nullptr;
    Job   ack_job = nullptr;
};

#endif
