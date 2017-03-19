#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "res/responser.h"
#include "prot/ip_pack.h"
#include "misc/net.h"

struct VpnKey{
    sockaddr_un src;
    sockaddr_un dst;
    Protocol    protocol;
    VpnKey(const Ip* ip);
    void reverse();
    const char* getstr() const;
}__attribute__((packed));

bool operator<(const VpnKey a, const VpnKey b);

struct VpnStatus{
    Responser* res_ptr;
    void*      res_index;
    VpnKey*    key;
    char*      packet;
    uint16_t   packet_len;
    uint32_t   seq;
    uint32_t   ack;
    uint16_t   window;

};


class Guest_vpn:public Requester, public ResObject{
protected:
    std::map<VpnKey, VpnStatus> statusmap;
    std::set<VpnKey*> waitlist;
    void defaultHE(uint32_t events) override;
    void buffHE(char* buff, size_t buflen);
    void tcpHE(const Ip* pac,const char* packet, size_t len);
    void udpHE(const Ip* pac,const char* packet, size_t len);
    void icmpHE(const Ip* pac,const char* packet, size_t len);
public:
    explicit Guest_vpn(int fd);
    virtual void wait(void* index)override;
    virtual void response(HttpResHeader&& res)override;
    virtual ssize_t Write(void* buff, size_t size, void* index)override;

    virtual void ResetResponser(Responser* r, void* index)override;
    virtual int32_t bufleft(void* index)override;
    virtual void clean(uint32_t errcode, void* index)override;
};

#endif
