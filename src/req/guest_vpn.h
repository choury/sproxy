#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/ip_pack.h"
#include "misc/net.h"
#include "misc/pcap.h"
#include "misc/buffer.h"

struct VpnKey{
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    explicit VpnKey(std::shared_ptr<const Ip> ip);
    const VpnKey& reverse();
    const char* getString(const char* sep) const;
    char version() const;
};

bool operator<(VpnKey a, VpnKey b);

#define VPN_TCP_WSCALE   9u

struct TcpStatus{
    uint32_t   sent_seq;
    uint32_t   sent_ack;
    uint32_t   recv_ack;
    uint32_t   want_seq; //收到的对方 seq+1，可以直接当作ack
    uint16_t   window;
    uint16_t   mss;
    uint64_t   options;
    uint8_t    recv_wscale;
    uint8_t    send_wscale;
    uint8_t    status;
};

struct IcmpStatus{
    uint16_t id;
    uint16_t seq;
};

#define VPN_DNSREQ_F    (1u<<16u)
struct VpnStatus{
    std::shared_ptr<HttpReq> req;
    std::shared_ptr<HttpRes> res;
    char*      packet;
    uint16_t   packet_len;
    void*      protocol_info;
    uint32_t   flags;
};

class Vpn_server;
class Guest_vpn:public Requester{
    VpnKey key;
    VpnStatus  status{};
    Vpn_server* server;
    const char* generateUA() const;
    const char* getProg() const;

    void aged();
    Job* aged_job = nullptr;
    void tcpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void udpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void icmpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void icmp6HE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void tcp_ack();

    void Recv_tcp(Buffer&& bb);
    void Recv_notcp(Buffer&& bb);
    int32_t bufleft();
    void handle(ChannelMessage::Signal s);
public:
    Guest_vpn(const VpnKey& key, Vpn_server* server);
    virtual ~Guest_vpn() override;

    void packetHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void writed();
    virtual void response(void*, std::shared_ptr<HttpRes> res) override;

    virtual void deleteLater(uint32_t error) override;
    virtual const char *getsrc() override;
    virtual void dump_stat(Dumper dp, void* param) override;
};


class Vpn_server {
    std::shared_ptr<RWer> rwer;
    std::map<VpnKey, Guest_vpn*> statusmap;
    int pcap = -1;
    void buffHE(const char* buff, size_t buflen);
public:
    explicit Vpn_server(int fd);
    virtual ~Vpn_server();

    void sendPkg(std::shared_ptr<Ip> pac, Buffer&& bb){
        pac->build_packet(bb);
        pcap_write_with_generated_ethhdr(pcap, bb.data(), bb.len);
        rwer->buffer_insert(rwer->buffer_end(), std::move(bb));
    }

    void sendPkg(std::shared_ptr<Ip> pac, const void* buff, size_t len){
        sendPkg(pac, Buffer{buff, len});
    }
    void sendPkg(std::shared_ptr<Ip> pac, std::nullptr_t){
        sendPkg(pac, Buffer{nullptr});
    }
    virtual int32_t bufleft();
    void cleanKey(const VpnKey& key);
};

#endif
