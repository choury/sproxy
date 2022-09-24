#ifndef ICMP_H__
#define ICMP_H__
#include "ipbase.h"

struct IcmpStatus;
void IcmpProc(std::shared_ptr<IcmpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
void SendData(std::shared_ptr<IcmpStatus> status, Buffer&& bb);

struct IcmpStatus: public IpStatus {
    uint16_t id = 0;
    uint16_t seq = 0;
    Job*   aged_job = nullptr;
    Job*   ack_job = nullptr;
};

#endif