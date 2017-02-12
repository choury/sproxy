#ifndef IP_PACKET_H_
#define IP_PACKET_H_

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef  __cplusplus
extern "C" {
#endif

#define SIZE_ETHERNET   0
#define SIZE_UDP_HEADER   8

#define PTYPE_TCP_SYN 1
#define PTYPE_TCP_DATA 2
#define PTYPE_TCP_ACK 3
#define PTYPE_TCP_RST 4
#define PTYPE_TCP_FIN 5
#define PTYPE_UNKNOW 0


/* check if flag existed in tcp header */
#define TCP_FL(th, flag)      (((th)->th_flags & flag) == flag)

typedef struct ip ip_hdr;
typedef struct tcphdr tcp_hdr;
typedef struct udphdr udp_hdr;

/*
 * Pseudo-header used for checksumming; this header should never
 * reach the wire
 */
typedef struct pseudo_hdr {
    uint32_t src;
    uint32_t dst;
    unsigned char mbz;
    unsigned char proto;
    uint16_t len;
} pseudo_hdr;

/*
 * TCP timestamp struct
 */
typedef struct tcp_timestamp {
    char kind;
    char length;
    uint32_t tsval __attribute__((__packed__));
    uint32_t tsecr __attribute__((__packed__));
    char padding[2];
} tcp_timestamp;

/*
 * TCP Maximum Segment Size
 */
typedef struct tcp_mss {
    char kind;
    char length;
    uint16_t mss __attribute__((__packed__));
} tcp_mss;

/**** class CapPacket, use for parse and build packet ****/
struct ip_packet {
    ip_hdr *ip; //ip头
    int iplen; //ip头长度
    tcp_hdr *tcp; //tcp头
    int tcplen; //tcp头长度
    udp_hdr *udp; //udp头
    int udplen; //udp头长度
    char *packet; //整个包的首地址
    int packetlen; //整个包的长度
    char *data; //数据部份的首地址
    int datalen; //数据的长度
    char *tcpopt; //tcp头选项
    unsigned int tcpoptlen; //tcp头选项长度
};


int parse_ip_packet(struct ip_packet* pac, char *packet);


char *build_mss(char **tcpopt, unsigned int *tcpopt_len,
                 uint16_t mss);

int get_timestamp(const struct tcphdr *tcp, uint32_t *tsval,
                   uint32_t *tsecr);

char *build_timestamp(char **tcpopt, unsigned int *tcpopt_len,
                       uint32_t tsval, uint32_t tsecr);

/* print header */
void print_ip_header(const struct ip_packet* pac);
void print_tcp_header(const struct ip_packet* pac);
void print_udp_header(const struct ip_packet* pac);

int getPacketType(const struct ip_packet* pac);

/* packet helper functions */
uint16_t checksum_comp(uint16_t *addr, int len);

/* build packet  */
char *build_tcpip_packet(const struct ip_packet* pac,
                         uint16_t window, uint8_t flags,
                         size_t* packetlen);

char *build_udpip_packet(const struct ip_packet*pac, unsigned int *packetlen);

#ifdef  __cplusplus
}
#endif

#endif //IP_PACKET_H_

