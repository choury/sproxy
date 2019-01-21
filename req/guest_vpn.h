#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/ip_pack.h"
#include "misc/net.h"

struct VpnKey{
    sockaddr_un src;
    sockaddr_un dst;
    Protocol    protocol;
    explicit VpnKey(std::shared_ptr<const Ip> ip);
    const VpnKey& reverse();
    const char* getString(const char* sep) const;
    char version() const;
};

bool operator<(VpnKey a, VpnKey b);


class Guest_vpn;

class VPN_nanny: public Server{
    std::map<VpnKey, std::weak_ptr<Guest_vpn>> statusmap;
    void buffHE(const char* buff, size_t buflen);
public:
    explicit VPN_nanny(int fd);
    virtual ~VPN_nanny() override;

    template <class T>
    void sendPkg(const std::shared_ptr<Ip>& pac, T* buff, size_t len){
        char* packet = pac->build_packet(buff, len);
        rwer->buffer_insert(rwer->buffer_end(), write_block{packet, len, 0});
    }
    virtual int32_t bufleft();
    virtual void dump_stat(Dumper dp, void* param) override;
    void cleanKey(const VpnKey& key);
};

#define VPN_TCP_WSCALE   4u

struct TcpStatus{
    uint32_t   send_seq;
    uint32_t   send_acked;
    uint32_t   want_seq;
    uint16_t   window;
    uint16_t   mss;
    uint16_t   options;
    uint8_t    recv_wscale;
    uint8_t    send_wscale;
    uint8_t    status;
};

struct IcmpStatus{
    uint16_t id;
    uint16_t seq;
};



class Guest_vpn:public Requester, virtual public RwObject{
    VpnKey key;
    VPN_nanny* nanny;
    std::weak_ptr<Responser>  res_ptr;
    void*       res_index;
    char*       packet;
    uint16_t    packet_len;
    void*       protocol_info;
    const char* generateUA() const;
    const char *getProg() const;

    void tcpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void udpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void icmpHE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    void icmp6HE(std::shared_ptr<const Ip> pac,const char* packet, size_t len);
    int aged();
    int tcp_ack();
public:
    Guest_vpn(const VpnKey& key, VPN_nanny* nanny);
    virtual ~Guest_vpn() override;

    void packetHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void writed();
    virtual void response(HttpResHeader* res) override;
    virtual void transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index) override;

    virtual int32_t bufleft(void* index) override;
    virtual void Send(void* buff, size_t size, void* index) override;

    virtual void finish(uint32_t flags, void* index) override;
    virtual void deleteLater(uint32_t error) override;
    virtual const char *getsrc(const void* index) override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

#endif
