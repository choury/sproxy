#ifndef GUEST_VPN_H__
#define GUEST_VPN_H__

#include "requester.h"
#include "res/responser.h"
#include "prot/ip_pack.h"

struct VpnStatus{
    Responser* res_ptr;
    void*      res_index;
    void*      key;
    char*      packet;
    uint16_t   packet_len;
    uint32_t seq;
    uint32_t ack;
};

class Guest_vpn:public Requester, public ResObject{
protected:
    std::map<std::string, VpnStatus> statusmap;
    std::set<std::string> waitlist;
    void defaultHE(uint32_t events) override;
    void buffHE(char* buff, size_t buflen);
    void tcpHE(const Ip* pac,const char* packet, size_t len);
    void udpHE(const Ip* pac,const char* packet, size_t len);
public:
    explicit Guest_vpn(int fd);
    virtual void wait(void* index)override;
    virtual void response(HttpResHeader&& res)override;
    virtual ssize_t Write(void* buff, size_t size, void* index)override;
    virtual ssize_t Write(const void* buff, size_t size, void* index)override;
    virtual void clean(uint32_t errcode, void* index)override;
};

#endif
