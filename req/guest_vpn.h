#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "prot/ip_pack.h"
#include "misc/net.h"

struct VpnKey{
    sockaddr_un src;
    sockaddr_un dst;
    Protocol    protocol;
    explicit VpnKey(const Ip* ip);
    void reverse();
    int getsport() const;
    const char* getdst() const;
};

bool operator<(const VpnKey a, const VpnKey b);

struct VpnStatus{
    Responser* res_ptr;
    void*      res_index;
    VpnKey*    key;
    char*      packet;
    uint16_t   packet_len;
    void*      protocol_info;
};

struct TcpStatus{
    uint32_t   send_seq;
    uint32_t   send_acked;
    uint32_t   want_seq;
    uint16_t   window;
    uint8_t    window_scale;
#define FIN_RECV   1
#define FIN_SEND   (1<<1)
    uint8_t    flags;
};

struct IcmpStatus{
    uint16_t id;
    uint16_t seq;
};


class Guest_vpn:public Requester, public ResObject{
    const char* generateUA(const VpnKey* key);
protected:
    std::map<VpnKey, VpnStatus> statusmap;
    void buffHE(const char* buff, size_t buflen);
    void tcpHE(const Ip* pac,const char* packet, size_t len);
    void udpHE(const Ip* pac,const char* packet, size_t len);
    void icmpHE(const Ip* pac,const char* packet, size_t len);
    template <class T>
    void sendPkg(Ip* pac, T* packet, size_t len);
    void cleanKey(const VpnKey* key);
    const char *getProg(const void* index) const;
public:
    explicit Guest_vpn(int fd);
    virtual ~Guest_vpn();
    virtual void response(HttpResHeader* res)override;
    virtual void transfer(void* index, Responser* res_ptr, void* res_index)override;

    virtual int32_t bufleft(void* index)override;
    virtual ssize_t Send(void* buff, size_t size, void* index)override;

    virtual void finish(uint32_t flags, void* index)override;
    virtual const char *getsrc(const void* index)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

#endif
