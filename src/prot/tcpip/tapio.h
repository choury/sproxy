#ifndef TAPIO_H__
#define TAPIO_H__

#include "tunio.h"

#include <array>
#include <unordered_map>
#include <netinet/in.h>
#ifdef __linux__
#include <linux/if_ether.h>
#else
#define ETH_ALEN 6
struct ethhdr {
    uint8_t h_dest[ETH_ALEN];
    uint8_t h_source[ETH_ALEN];
    uint16_t h_proto;
};
#endif

constexpr size_t ETH_HDR_LEN = sizeof(ethhdr);
using MacAddr = std::array<uint8_t, ETH_ALEN>;

struct MacAddrHash {
    size_t operator()(const std::array<uint8_t, 16>& k) const {
        size_t h = 0;
        for (auto b : k) h = h * 31 + b;
        return h;
    }
};

class TapRWer: public TunRWer {
    // Map from IP to MAC for outgoing frame destination
    std::unordered_map<uint32_t, MacAddr> macCache4;
    std::unordered_map<std::array<uint8_t, 16>, MacAddr, MacAddrHash> macCache6;

    void learnMac(const ethhdr* eth, const char* ip_data, bool is_ipv6);
    void SendFrame(const uint8_t* dstMac, uint16_t proto, Buffer&& bb, const GsoInfo& gso, int ip_hdr_len);
protected:
    virtual void ProcessPacket(Buffer&& bb) override;
    virtual void SendPkg(std::shared_ptr<Ip> pac, Buffer&& bb, const GsoInfo& gso) override;
public:
    explicit TapRWer(int fd, bool enable_offload, std::shared_ptr<IRWerCallback> cb);
    virtual ~TapRWer() override = default;
    virtual Destination getSrc() const override {
        Destination src{};
        strcpy(src.hostname, "<tap>");
        return src;
    }
};

#endif
