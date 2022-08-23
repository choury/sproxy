#ifndef IP_PACKET_H_
#define IP_PACKET_H_

#include "misc/net.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#ifdef HAVE_GUN_SOURCE_BUG
#define __FAVOR_BSD    1
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <memory>

#ifndef TH_FIN
#define TH_FIN        0x01
#endif

#ifndef TH_SYN
#define TH_SYN        0x02
#endif

#ifndef TH_RST
#define TH_RST        0x04
#endif

#ifndef TH_PUSH
#define TH_PUSH       0x08
#endif

#ifndef TH_ACK
#define TH_ACK        0x10
#endif

#ifndef TH_URG
#define TH_URG        0x20
#endif

#ifndef TCP_MAXWIN
#define TCP_MAXWIN 65535
#endif

#ifndef TCP_MSS
#define TCP_MSS  512
#endif

#ifdef __APPLE__
struct icmphdr
{
  uint8_t type;		/* message type */
  uint8_t code;		/* type sub-code */
  uint16_t checksum;
  union
  {
    struct
    {
      uint16_t	id;
      uint16_t	sequence;
    } echo;			/* echo datagram */
    uint32_t	gateway;	/* gateway address */
    struct
    {
      uint16_t	___unused;
      uint16_t	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

#endif

class Buffer;
class Icmp{
    icmphdr icmp_hdr;
public:
    bool valid = true;
    Icmp();
    Icmp(const char* packet, size_t len);
    void print() const;
    void build_packet(Buffer& bb);

    Icmp* settype(uint8_t type);
    Icmp* setcode(uint8_t code);
    Icmp* setid(uint16_t id);
    Icmp* setseq(uint16_t seq);

    uint8_t gettype()const;
    uint8_t getcode()const;
    uint16_t getid()const;
    uint16_t getseq()const;
};

class Icmp6{
    icmp6_hdr icmp_hdr;
public:
    bool valid = true;
    Icmp6();
    Icmp6(const char* packet, size_t len);
    void print() const;
    void build_packet(const ip6_hdr* iphdr, Buffer& bb);

    Icmp6* settype(uint8_t type);
    Icmp6* setcode(uint8_t code);
    Icmp6* setid(uint16_t id);
    Icmp6* setseq(uint16_t seq);

    uint8_t gettype()const;
    uint8_t getcode()const;
    uint16_t getid()const;
    uint16_t getseq()const;
};

struct Sack{
    uint32_t left;
    uint32_t right;
    struct Sack* next;
};

void sack_release(Sack** sack);

class Tcp{
    tcphdr tcp_hdr; //tcp头
    char *tcpopt = nullptr; //tcp头选项
    size_t tcpoptlen = 0; //tcp头选项长度
public:
    bool valid = true;
    uint8_t hdrlen = 0;
    Tcp(const char* packet, size_t len);
    Tcp(uint16_t sport, uint16_t dport);
    Tcp(const Tcp&) = delete;
    void print() const;
    void build_packet(const ip* ip_hdr, Buffer& bb);
    void build_packet(const ip6_hdr* ip_hdr, Buffer& bb);


    Tcp* setack(uint32_t ack);
    Tcp* setseq(uint32_t seq);
    Tcp* setwindow(uint32_t window);
    Tcp* setflag(uint8_t flag);
    Tcp* setmss(uint16_t mss);
    Tcp* settimestamp(uint32_t tsval, uint32_t tsecr);
    Tcp* setwindowscale(uint8_t scale);
    Tcp* setsack(const struct Sack* sack);
    uint32_t getack() const;
    uint32_t getseq() const;
    uint16_t getsport() const;
    uint16_t getdport() const;
    uint16_t getwindow() const;
    uint8_t  getflag() const;
    const char* getflags() const;
    uint64_t  getoptions() const;
    uint16_t getmss() const;
    int gettimestamp(uint32_t *tsval, uint32_t *tsecr) const;
    uint8_t getwindowscale() const;
    void getsack(struct Sack** sack) const;
    ~Tcp();
};

class Udp{
    udphdr udp_hdr; //udp头
public:
    bool valid = true;
    Udp(const char* packet, size_t len);
    Udp(uint16_t sport, uint16_t dport);
    void print() const;
    void build_packet(const ip* ip_hdr, Buffer& bb);
    void build_packet(const ip6_hdr* ip_hdr, Buffer& bb);

    uint16_t getsport() const;
    uint16_t getdport() const;
};

class Ip{
protected:
    uint8_t hdrlen = 0;
    uint8_t type;
    virtual void print() const = 0;
    bool valid = true;
public:
    union {
        Icmp* icmp = nullptr;
        Icmp6* icmp6;
        Tcp* tcp;
        Udp* udp;
    };
    virtual ~Ip();

    virtual sockaddr_storage getsrc() const = 0;
    virtual sockaddr_storage getdst() const = 0;
    virtual void dump() const;

    virtual size_t gethdrlen() const;
    virtual uint8_t gettype() const;
    virtual void build_packet(Buffer& bb) = 0;
    virtual bool isValid();
};

std::shared_ptr<Ip> MakeIp(const void* packet, size_t len);
std::shared_ptr<Ip> MakeIp(uint8_t type, const sockaddr_storage* src,  const sockaddr_storage* dst);

class Ip4: public Ip {
    ip hdr; //ip头
    Ip4(const char* packet, size_t len);
    Ip4(uint8_t type, uint16_t sport, uint16_t dport);
    Ip4(uint8_t type, const in_addr* src, uint16_t sport, const in_addr* dst, uint16_t dport);
    Ip4(uint8_t type, const sockaddr_storage* src,  const sockaddr_storage* dst);
    void print() const override;
public:
    Ip4(const Ip4&) = delete;
    sockaddr_storage getsrc() const override;
    sockaddr_storage getdst() const override;

    void build_packet(Buffer& bb) override;

    friend std::shared_ptr<Ip> MakeIp(const void* packet, size_t len);
    friend std::shared_ptr<Ip> MakeIp(uint8_t type, const sockaddr_storage* src,  const sockaddr_storage* dst);
};

class Ip6: public Ip {
    ip6_hdr hdr; //ip头
    Ip6(const char* packet, size_t len);
    Ip6(uint8_t type, uint16_t sport, uint16_t dport);
    Ip6(uint8_t type, const in6_addr* src, uint16_t sport, const in6_addr* dst, uint16_t dport);
    Ip6(uint8_t type, const sockaddr_storage* src,  const sockaddr_storage* dst);
    void print() const override;
public:
    Ip6(const Ip6&) = delete;
    sockaddr_storage getsrc() const override;
    sockaddr_storage getdst() const override;

    void build_packet(Buffer& bb)override;

    friend std::shared_ptr<Ip> MakeIp(const void* packet, size_t len);
    friend std::shared_ptr<Ip> MakeIp(uint8_t type, const sockaddr_storage* src,  const sockaddr_storage* dst);
};

#endif //IP_PACKET_H_
