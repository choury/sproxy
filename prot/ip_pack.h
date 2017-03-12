#ifndef IP_PACKET_H_
#define IP_PACKET_H_

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define PTYPE_TCP_SYN  1
#define PTYPE_TCP_DATA 2
#define PTYPE_TCP_ACK  3
#define PTYPE_TCP_RST  4
#define PTYPE_TCP_FIN  5
#define PTYPE_UNKNOW 0



class Icmp{
    icmphdr icmp_hdr;
public:
    Icmp();
    Icmp(const char* packet, size_t len);
    void print() const;
    char *build_packet(const void* data, size_t &len);
    
    Icmp* settype(uint8_t type);
    Icmp* setcode(uint8_t code);

    uint8_t gettype()const;
    uint8_t getcode()const;
};


class Tcp{
    const ip* ip_hdr = nullptr;
    tcphdr tcp_hdr; //tcp头
    char *tcpopt = nullptr; //tcp头选项
    size_t tcpoptlen = 0; //tcp头选项长度
public:
    uint8_t hdrlen = 0;
    Tcp(const ip* ip_hdr, const char* packet, size_t len);
    Tcp(const ip* ip_hdr, uint16_t sport, uint16_t dport);
    void print() const;
    char *build_packet(const void* data, size_t &len);


    Tcp* setack(uint32_t ack);
    Tcp* setseq(uint32_t seq);
    Tcp* setwindow(uint32_t window);
    Tcp* setflag(uint8_t flag);
    Tcp* setmss(uint16_t mss);
    Tcp* settimestamp(uint32_t tsval, uint32_t tsecr);
    uint32_t getack() const;
    uint32_t getseq() const;
    uint16_t getsport() const;
    uint16_t getdport() const;
    uint8_t  getflag() const;
    int gettimestamp(uint32_t *tsval, uint32_t *tsecr) const;
    ~Tcp();
};

class Udp{
    const ip* ip_hdr = nullptr;
    udphdr udp_hdr; //udp头
public:
    Udp(const ip* ip_hdr, const char* packet, size_t len);
    Udp(const ip* ip_hdr, uint16_t sport, uint16_t dport);
    void print() const;
    char *build_packet(const void* data, size_t &len);

    uint16_t getsport() const;
    uint16_t getdport() const;
};

/**** class CapPacket, use for parse and build packet ****/
class Ip {
    ip ip_hdr; //ip头
    Ip(uint8_t type, uint16_t sport, uint16_t dport);
public:
    uint8_t hdrlen = 0;
    union {
        Icmp* icmp;
        Tcp* tcp;
        Udp* udp;
    };
    Ip(const char* packet, size_t len);
    Ip(uint8_t type, const char* src, uint16_t sport, const char* dst, uint16_t dport);
    Ip(uint8_t type, const in_addr* src, uint16_t sport, const in_addr* dst, uint16_t dport);
    void print() const;
    const in_addr* getsrc() const;
    const in_addr* getdst() const;
    uint8_t gettype() const;
    size_t gethdrlen() const;
    char* build_packet(const void* data, size_t &len);
    
    ~Ip();
};

#endif //IP_PACKET_H_
