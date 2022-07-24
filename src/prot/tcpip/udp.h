#ifndef UDP_H__
#define UDP_H__

#include "ipbase.h"

struct UdpStatus;

class UdpHE: virtual public IpBase {
public:
    void DefaultProc(std::shared_ptr<IpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void SendData(std::shared_ptr<IpStatus> status, Buffer&& bb);
};


struct UdpStatus: public IpStatus{
    size_t readlen  = 0;
    Job*   aged_job = nullptr;
    Job*   ack_job = nullptr;
};

#endif
