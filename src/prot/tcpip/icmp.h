#ifndef ICMP_H__
#define ICMP_H__
#include "ipbase.h"

struct IcmpStatus;
class IcmpHE: virtual public IpBase {
public:
    void DefaultProc(std::shared_ptr<IpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void SendData(std::shared_ptr<IpStatus> status, Buffer&& bb);
};

struct IcmpStatus: public IpStatus {
    uint16_t id = 0;
    uint16_t seq = 0;
    Job*   aged_job = nullptr;
};

#endif