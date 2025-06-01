#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/tcpip/ip_pack.h"
#include "prot/http/http_header.h"
#include "prot/memio.h"
#include "misc/job.h"

#define VPN_DNSREQ_F    (1u<<16u)
#define TUN_CLOSED_F    (1u<<17u)

class Guest_vpn: public Requester {
    struct VpnStatus{
        std::string host;
        std::string prog;
        std::shared_ptr<const Ip> pac;
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IMemRWerCallback> cb;
        uint32_t   flags = 0;
        Job        cleanJob = nullptr;
    };

    std::map<uint64_t, VpnStatus> statusmap;
    void ReqProc(uint64_t id, std::shared_ptr<const Ip> pac);
    void Clean(uint64_t id);

    size_t Recv(Buffer&& bb);
    virtual std::shared_ptr<IMemRWerCallback> response(uint64_t id) override;
public:
    explicit Guest_vpn(int fd, bool enable_offload);
    virtual ~Guest_vpn() override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif
