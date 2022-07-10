#ifndef IP_H__
#define IP_H__

#include "common/common.h"
#include "ip_pack.h"
#include "misc/buffer.h"
#include "misc/job.h"
#include <unistd.h>

struct IpStatus;
class IpBase{
protected:
    virtual void ErrProc(std::shared_ptr<const Ip> pac, uint32_t code) = 0;
    virtual void ReqProc(std::shared_ptr<const Ip> pac) = 0;
    virtual bool DataProc(std::shared_ptr<const Ip> pac, const void* data, size_t len) = 0;
    virtual void sendPkg(std::shared_ptr<Ip> pac, Buffer&& bb) = 0;
public:
    void Unreach(std::shared_ptr<IpStatus> status, uint8_t code);
    ssize_t Cap(std::shared_ptr<IpStatus>) {
        return MAX_BUF_LEN;
    }
};

struct IpStatus;
typedef void (IpBase::*InProc_t)(std::shared_ptr<IpStatus>, std::shared_ptr<const Ip>, const char*, size_t);
typedef void (IpBase::*Write_t)(std::shared_ptr<IpStatus>, Buffer&&);
#define IP_PORT_UNREACH 1
#define IP_ADDR_UNREACH 2
typedef void (IpBase::*Unreach_t)(std::shared_ptr<IpStatus>, uint8_t code);
typedef ssize_t (IpBase::*Cap_t)(std::shared_ptr<IpStatus>);
struct IpStatus{
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    std::shared_ptr<Block> packet_hdr;
    job_handler jobHandler;
    uint16_t    packet_hdr_len;
    InProc_t    InProc;
    Write_t     Write;
    Unreach_t   Unreach;
    Cap_t       Cap;
};

#endif
