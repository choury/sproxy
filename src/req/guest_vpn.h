#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/ip_pack.h"
#include "misc/net.h"

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

#define VPN_TCP_WSCALE   4u

struct TcpStatus{
    uint32_t   send_seq;
    uint32_t   send_ack;
    uint32_t   acked;
    uint32_t   want_seq;
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

struct VpnStatus{
    HttpReq* req;
    HttpRes* res;
    char*      packet;
    uint16_t   packet_len;
    void*      protocol_info;
    uint32_t flags;
};

class Vpn_server;
class Guest_vpn:public Requester{
    VpnKey key;
    VpnStatus  status;
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

    void Send_tcp(const void* buff, size_t size);
    void Send_notcp(void* buff, size_t size);
    int32_t bufleft();
    void handle(Channel::signal s);
public:
    Guest_vpn(const VpnKey& key, Vpn_server* server);
    virtual ~Guest_vpn() override;

    void packetHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void writed();
    virtual void response(void*, HttpRes* res) override;

    virtual void deleteLater(uint32_t error) override;
    virtual const char *getsrc() override;
    virtual void dump_stat(Dumper dp, void* param) override;
};


class Vpn_server {
    RWer* rwer = nullptr;
    std::map<VpnKey, Guest_vpn*> statusmap;
    void buffHE(const char* buff, size_t buflen);
public:
    explicit Vpn_server(int fd);
    virtual ~Vpn_server();

    template <class T>
    void sendPkg(const std::shared_ptr<Ip>& pac, T* buff, size_t len){
        char* packet = pac->build_packet(buff, len);
        rwer->buffer_insert(rwer->buffer_end(), write_block{packet, len, 0});
    }
    virtual int32_t bufleft();
    void cleanKey(const VpnKey& key);
};

#endif
