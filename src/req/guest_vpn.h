#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/tcpip/ip_pack.h"
#include "prot/memio.h"

#define VPN_DNSREQ_F    (1u<<16u)

class Guest_vpn: public Requester {
    struct VpnStatus{
        std::string host;
        std::shared_ptr<const Ip> pac;
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        std::shared_ptr<MemRWer> rwer; //rwer 和 req/res 二者只会有一个
        uint32_t   flags = 0;
    };

    std::map<uint64_t, VpnStatus> statusmap;
    void handle(uint64_t id, ChannelMessage::Signal s);
    void ReqProc(uint64_t id, std::shared_ptr<const Ip> pac);
    void Clean(uint64_t id, VpnStatus& status);
    int mread(uint64_t id, Buffer&& bb);
public:
    explicit Guest_vpn(int fd);
    virtual void response(void* index, std::shared_ptr<HttpRes> res) override;
    virtual ~Guest_vpn();
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif
