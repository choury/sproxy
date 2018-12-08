#include "ip_pack.h"
#include "common.h"
#include "misc/util.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <assert.h>


#define UDP_CHECKSUM

/*
 * Pseudo-header used for checksumming; this header should never
 * reach the wire
 */
typedef struct pseudo_hdr {
    in_addr src;
    in_addr dst;
    unsigned char mbz;
    unsigned char proto;
    uint16_t len;
} __attribute__((packed)) pseudo_hdr;

typedef struct pseudo_hdr6 {
    in6_addr src;
    in6_addr dst;
    uint32_t len;
    uint8_t zero[3];
    uint8_t proto;
} __attribute__((packed)) pseudo_hdr6;



typedef struct tcp_opt{
    uint8_t kind;
    uint8_t length;
    uint8_t data[0];
} __attribute__((packed)) tcp_opt;

/*
 * TCP timestamp struct
 */
typedef struct tcp_timestamp {
    char kind;
    char length;
    uint32_t tsval;
    uint32_t tsecr;
    char padding[2];
} __attribute__((packed)) tcp_timestamp;

/*
 * TCP Maximum Segment Size
 */
typedef struct tcp_mss {
    char kind;
    char length;
    uint16_t mss;
} __attribute__((packed)) tcp_mss;

typedef struct tcp_windowscale{
    uint8_t kind;
    uint8_t length;
    uint8_t scale;
    uint8_t padding;
} __attribute__((packed)) tcp_windowscale;


/**
  * calculate checksum in ip/tcp header
  */
static uint16_t checksum16(uint8_t *addr, int len) {
    long sum = 0;

    while (len > 1) {
        sum += (*addr++) << 8;
        sum += *addr++;
        len -= 2;
    }
    if (len > 0)
        sum += (*addr)<<8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~(uint16_t)sum;
}


static uint16_t ip_checksum(const ip* ip_hdr, uint8_t protocol, void* data, size_t len){
    if(ip_hdr == nullptr){
        return 0;
    }

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *)p_move(data, -(char)sizeof(pseudo_hdr));
    phdr->src = ip_hdr->ip_src;
    phdr->dst = ip_hdr->ip_dst;
    phdr->mbz = 0;
    phdr->proto = protocol;
    phdr->len = htons(len);
    /* tcp checksum */
    uint16_t cksum = checksum16((uint8_t*)phdr, len  + sizeof(pseudo_hdr));
    p_move(phdr, sizeof(pseudo_hdr));
    return htons(cksum);
}

static uint16_t ip6_checksum(const ip6_hdr* ip_hdr, uint8_t protocol, void* data, size_t len){
    if(ip_hdr == nullptr){
        return 0;
    }
    /* pseudo header used for checksumming */
    pseudo_hdr6 *phdr = (struct pseudo_hdr6 *)p_move(data, -(char)sizeof(pseudo_hdr6));
    phdr->src = ip_hdr->ip6_src;
    phdr->dst = ip_hdr->ip6_dst;
    memset(phdr->zero, 0, sizeof(phdr->zero));
    phdr->proto = protocol;
    phdr->len = htonl(len);
    /* tcp checksum */
    uint16_t cksum = checksum16((uint8_t*)phdr, len  + sizeof(pseudo_hdr6));
    p_move(phdr, sizeof(pseudo_hdr6));
    return htons(cksum);
}

Icmp::Icmp() {
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
}

Icmp::Icmp(const char* packet, size_t len){
    if(len < sizeof(icmp_hdr)){
        LOGE("Invalid ICMP header length: %zu bytes\n", len);
        throw 0;
    }
    memcpy(&icmp_hdr, packet, sizeof(icmp_hdr));
}


void Icmp::print() const {
    LOGD(DVPN,"ICMP header: "
    "type: %d, "
    "code: %d, "
    "checksum: %d\n",

        icmp_hdr.type,
        icmp_hdr.code,
        icmp_hdr.checksum
    );
}

Icmp* Icmp::settype(uint8_t type) {
    icmp_hdr.type = type;
    return this;
}

Icmp* Icmp::setcode(uint8_t code) {
    icmp_hdr.code = code;
    return this;
}

Icmp* Icmp::setid(uint16_t id){
    assert(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY);
    icmp_hdr.un.echo.id = htons(id);
    return this;
}

Icmp* Icmp::setseq(uint16_t seq){
    assert(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY);
    icmp_hdr.un.echo.sequence = htons(seq);
    return this;
}

uint8_t Icmp::gettype() const {
    return icmp_hdr.type;
}

uint8_t Icmp::getcode() const {
    return icmp_hdr.code;
}

uint16_t Icmp::getid() const {
    if(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY){
        return ntohs(icmp_hdr.un.echo.id);
    }
    return 0;
}

uint16_t Icmp::getseq() const {
    assert(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY);
    return ntohs(icmp_hdr.un.echo.sequence);
}

char* Icmp::build_packet(void* data, size_t& len) {
    assert(data);
    len = len + sizeof(icmp_hdr);
    char* packet = (char *)p_move(data, -(char)sizeof(icmp_hdr));
    icmp_hdr.checksum = 0;
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
    ((icmp *)packet)->icmp_cksum = htons(checksum16((uint8_t*) packet, len));
    return packet;
}

Icmp6::Icmp6() {
    memset(&icmp_hdr, 0 ,sizeof(icmp_hdr));
}

Icmp6::Icmp6(const char* packet, size_t len){
    if(len < sizeof(icmp_hdr)){
        LOGE("Invalid ICMPV6 header length: %zu bytes\n", len);
        throw 0;
    }
    memcpy(&icmp_hdr, packet, sizeof(icmp_hdr));
}

void Icmp6::print() const {
    LOGD(DVPN,"ICMPV6 header: "
    "type: %d, "
    "code: %d, "
    "checksum: %d\n",

        icmp_hdr.icmp6_type,
        icmp_hdr.icmp6_code,
        icmp_hdr.icmp6_cksum
    );
}

Icmp6* Icmp6::settype(uint8_t type) {
    icmp_hdr.icmp6_type = type;
    return this;
}

Icmp6* Icmp6::setcode(uint8_t code) {
    icmp_hdr.icmp6_code = code;
    return this;
}

Icmp6* Icmp6::setid(uint16_t id){
    assert(icmp_hdr.icmp6_type == ICMP6_ECHO_REQUEST || icmp_hdr.icmp6_type == ICMP6_ECHO_REPLY);
    icmp_hdr.icmp6_id = htons(id);
    return this;
}

Icmp6* Icmp6::setseq(uint16_t seq){
    assert(icmp_hdr.icmp6_type == ICMP6_ECHO_REQUEST || icmp_hdr.icmp6_type == ICMP6_ECHO_REPLY);
    icmp_hdr.icmp6_seq = htons(seq);
    return this;
}

uint8_t Icmp6::gettype() const {
    return icmp_hdr.icmp6_type;
}

uint8_t Icmp6::getcode() const {
    return icmp_hdr.icmp6_code;
}

uint16_t Icmp6::getid() const {
    if(icmp_hdr.icmp6_type == ICMP6_ECHO_REQUEST || icmp_hdr.icmp6_type == ICMP6_ECHO_REPLY){
        return ntohs(icmp_hdr.icmp6_id);
    }
    return 0;
}

uint16_t Icmp6::getseq() const {
    assert(icmp_hdr.icmp6_type == ICMP6_ECHO_REQUEST || icmp_hdr.icmp6_type == ICMP6_ECHO_REPLY);
    return ntohs(icmp_hdr.icmp6_seq);
}

char* Icmp6::build_packet(const ip6_hdr* ip_hdr, void* data, size_t& len) {
    assert(data);
    len = len + sizeof(icmp6_hdr);
    char* packet = (char *)p_move(data, -(char)sizeof(icmp_hdr));
    icmp_hdr.icmp6_cksum = 0;
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
    ((icmp6_hdr *)packet)->icmp6_cksum = ip6_checksum(ip_hdr, IPPROTO_ICMPV6, packet, len);
    return packet;
}

Tcp::Tcp(const char* packet, size_t len){
    memcpy(&tcp_hdr, packet, sizeof(struct tcphdr));
    hdrlen = tcp_hdr.th_off * 4;
    if (hdrlen < 20) {
        LOGE("Invalid TCP header length: %u bytes\n", hdrlen);
        throw 0;
    }
    if( len < hdrlen){
        LOGE("Invalid TCP packet length: %zu bytes\n", len);
        throw 0;
    }
    tcpoptlen = hdrlen - sizeof(struct tcphdr);
    if(tcpoptlen){
        tcpopt = (char *)malloc(tcpoptlen);
        memcpy(tcpopt, packet+sizeof(struct tcphdr), tcpoptlen);
    }
}

Tcp::Tcp(uint16_t sport, uint16_t dport){
    memset(&tcp_hdr, 0, sizeof(tcphdr));
    
    tcp_hdr.th_sport = htons(sport);
    tcp_hdr.th_dport = htons(dport);

    tcp_hdr.th_off = 5;
}

Tcp::~Tcp() {
    free(tcpopt);
}



Tcp * Tcp::setseq(uint32_t seq) {
    tcp_hdr.th_seq = htonl(seq);
    return this;
}


Tcp * Tcp::setack(uint32_t ack) {
    tcp_hdr.th_ack = htonl(ack);
    return this;
}

Tcp * Tcp::setwindow(uint32_t window) {
    if(window > TCP_MAXWIN){
        tcp_hdr.th_win = htons(TCP_MAXWIN);
    }else{
        tcp_hdr.th_win = htons(window);
    }
    return this;
}

Tcp * Tcp::setflag(uint8_t flag) {
    ((uint8_t *)&tcp_hdr)[13] = flag;
    return this;
}


/**
 * Build TCP timestamp option
 * tcpopt points to possibly already existing TCP options
 * so inspect current TCP option length (tcpopt_len)
 */
Tcp* Tcp::settimestamp(uint32_t tsval, uint32_t tsecr) {
    if(tsval == 0){
        tsval = time(0);
    }
    if (tcpopt) {
        tcpopt = (char *) realloc(tcpopt, tcpoptlen + sizeof(tcp_timestamp));
    } else{
        assert(tcpoptlen == 0);
        tcpopt = (char *) malloc(sizeof(tcp_timestamp));
    }

    tcp_timestamp *t = (tcp_timestamp *)(tcpopt+tcpoptlen);

    memset(t, TCPOPT_NOP, sizeof(tcp_timestamp));
    t->kind = TCPOPT_TIMESTAMP;
    t->length = TCPOLEN_TIMESTAMP;

    t->tsval = htonl(tsval);
    t->tsecr = htonl(tsecr);

    tcpoptlen += sizeof(tcp_timestamp);
    return this;
}

/**
 * Build TCP Maximum Segment Size option
 */
Tcp* Tcp::setmss(uint16_t mss) {
    if (tcpopt) {
        tcpopt = (char *)realloc(tcpopt, tcpoptlen + sizeof(tcp_mss));
    } else{
        assert(tcpoptlen == 0);
        tcpopt = (char *) malloc(sizeof(tcp_mss));
    }
    struct tcp_mss *t = (tcp_mss *)(tcpopt + tcpoptlen);

    memset(t, TCPOPT_NOP, sizeof(tcp_mss));
    t->kind = TCPOPT_MAXSEG;
    t->length = TCPOLEN_MAXSEG;
    t->mss = htons(mss);

    tcpoptlen += sizeof(tcp_mss);

    return this;
}

Tcp* Tcp::setwindowscale(uint8_t scale) {
    if (tcpopt) {
        tcpopt = (char *)realloc(tcpopt, tcpoptlen + sizeof(tcp_windowscale));
    } else{
        assert(tcpoptlen == 0);
        tcpopt = (char *) malloc(sizeof(tcp_windowscale));
    }
    struct tcp_windowscale *t = (tcp_windowscale *)(tcpopt + tcpoptlen);

    memset(t, TCPOPT_NOP, sizeof(tcp_windowscale));
    t->kind = TCPOPT_WINDOW;
    t->length = TCPOLEN_WINDOW;
    t->scale = scale;

    tcpoptlen += sizeof(tcp_windowscale);
    return this;
}


char * Tcp::build_packet(const ip* ip_hdr, void* data, size_t& len) {
    if (tcpoptlen % 4) {
        LOGE("TCP option length must be divisible by 4.\n");
        return 0;
    }
    assert(data);

    len = sizeof(tcphdr) + tcpoptlen + len;
    tcp_hdr.th_off = (sizeof(tcphdr) + tcpoptlen) >> 2;
    tcp_hdr.th_sum = 0;

    char* packet = (char *) p_move(data, -(char)(sizeof(tcphdr)+tcpoptlen));
    memcpy(packet, &tcp_hdr, sizeof(tcphdr));
    if (tcpoptlen > 0)
        memcpy(packet + sizeof(tcphdr), tcpopt, tcpoptlen); //copy tcp header option to packet

    ((tcphdr *)packet)->th_sum = ip_checksum(ip_hdr, IPPROTO_TCP, packet, len);
    return packet;
}

char * Tcp::build_packet(const ip6_hdr* ip_hdr, void* data, size_t& len) {
    if (tcpoptlen % 4) {
        LOGE("TCP option length must be divisible by 4.\n");
        return 0;
    }
    assert(data);

    len = sizeof(tcphdr) + tcpoptlen + len;
    tcp_hdr.th_off = (sizeof(tcphdr) + tcpoptlen) >> 2;
    tcp_hdr.th_sum = 0;

    char* packet = (char *) p_move(data, -(char)(sizeof(tcphdr)+tcpoptlen));
    memcpy(packet, &tcp_hdr, sizeof(tcphdr));
    if (tcpoptlen > 0)
        memcpy(packet + sizeof(tcphdr), tcpopt, tcpoptlen); //copy tcp header option to packet

    ((tcphdr *)packet)->th_sum = ip6_checksum(ip_hdr, IPPROTO_TCP, packet, len);
    return packet;
}


uint16_t Tcp::getoptions() const {
    tcp_opt* opt = (tcp_opt *)tcpopt;
    size_t len = tcpoptlen;
    uint16_t options = 0;

    while (len > 0 && opt) {
        if (opt->kind == TCPOPT_EOL)
            break;
        if(opt->kind == TCPOPT_NOP){
            len --;
            opt = (tcp_opt*)((char *)opt+1);
            continue;
        }
        assert(opt->kind<16);
        options |= (1<<opt->kind);
        len -= opt->length;
        opt = (tcp_opt*)((char *)opt+opt->length);
    }
    return options;
}

uint16_t Tcp::getmss() const{
    tcp_opt* opt = (tcp_opt *)tcpopt;
    size_t len = tcpoptlen;

    while (len > 0 && opt) {
        if (opt->kind == TCPOPT_EOL)
            break;
        if(opt->kind == TCPOPT_NOP){
            len --;
            opt = (tcp_opt*)((char *)opt+1);
            continue;
        }
        if (opt->kind == TCPOPT_MAXSEG) {
            assert(opt->length == TCPOLEN_MAXSEG);
            struct tcp_mss *t = (tcp_mss *)(opt);
            return ntohs(t->mss);
        }
        len -= opt->length;
        opt = (tcp_opt*)((char *)opt+opt->length);
    }
    return TCP_MSS;
}

/**
 * Parse TCP options and get timestamp if it exists.
 * Return 1 if timestamp valid, 0 for failure
 */
int Tcp::gettimestamp(uint32_t *tsval, uint32_t *tsecr) const{
    if (!tsval || !tsecr)
        return -1;

    tcp_opt* opt = (tcp_opt *)tcpopt;
    size_t len = tcpoptlen;

    while (len > 0 && opt) {
        if (opt->kind == TCPOPT_EOL)
            break;
        if(opt->kind == TCPOPT_NOP){
            len --;
            opt = (tcp_opt*)((char *)opt+1);
            continue;
        }
        if (opt->kind == TCPOPT_TIMESTAMP) {
            assert(opt->length == TCPOLEN_TIMESTAMP);
            tcp_timestamp *timestamp = (tcp_timestamp *)opt;
            *tsval = ntohl(timestamp->tsval);
            *tsecr = ntohl(timestamp->tsecr);
            return 1;
        }
        len -= opt->length;
        opt = (tcp_opt*)((char *)opt+opt->length);
    }
    *tsval = 0;
    *tsecr = 0;
    return 0;
}

uint8_t Tcp::getwindowscale() const{
    tcp_opt* opt = (tcp_opt *)tcpopt;
    size_t len = tcpoptlen;

    while (len > 0 && opt) {
        if (opt->kind == TCPOPT_EOL)
            break;
        if(opt->kind == TCPOPT_NOP){
            len --;
            opt = (tcp_opt*)((char *)opt+1);
            continue;
        }
        if (opt->kind == TCPOPT_WINDOW) {
            assert(opt->length == TCPOLEN_WINDOW);
            return opt->data[0];
        }
        len -= opt->length;
        opt = (tcp_opt*)((char *)opt+opt->length);
    }
    return 0;
}

uint32_t Tcp::getseq() const {
    return ntohl(tcp_hdr.th_seq);
}

uint32_t Tcp::getack() const {
    return ntohl(tcp_hdr.th_ack);
}

uint16_t Tcp::getsport() const {
    return ntohs(tcp_hdr.th_sport);
}

uint16_t Tcp::getdport() const {
    return ntohs(tcp_hdr.th_dport);
}

uint16_t Tcp::getwindow() const {
    return ntohs(tcp_hdr.th_win);
}


uint8_t Tcp::getflag() const {
    return ((uint8_t *)&tcp_hdr)[13];
}

/**
 * 输出tcp头
 */
void Tcp::print() const{
    LOGD(DVPN,"TCP header: "
    "Src port: %d, "
    "Dst port: %d, "
    "Seq num: %u, "
    "Ack num: %u, "
    "Length: %u, "
    "FIN= %d, "
    "SYN= %d, "
    "RST= %d, "
    "PSH= %d, "
    "ACK= %d, "
    "URG= %d, "
    "Window size: %d, "
    "Checksum: %d, "
    "Urgent point: %d\n",

         ntohs(tcp_hdr.th_sport),
         ntohs(tcp_hdr.th_dport),
         ntohl(tcp_hdr.th_seq),
         ntohl(tcp_hdr.th_ack),
         tcp_hdr.th_off * 4,
         tcp_hdr.th_flags & TH_FIN,
         tcp_hdr.th_flags & TH_SYN,
         tcp_hdr.th_flags & TH_RST,
         tcp_hdr.th_flags & TH_PUSH,
         tcp_hdr.th_flags & TH_ACK,
         tcp_hdr.th_flags & TH_URG,
         ntohs(tcp_hdr.th_win),
         ntohs(tcp_hdr.th_sum),
         ntohs(tcp_hdr.th_urp));
    
    tcp_opt *opt = (tcp_opt*)tcpopt;
    size_t len = tcpoptlen;
    while(len > 0 && opt){
        if(opt->kind == TCPOPT_EOL){
            break;
        }
        if(opt->kind == TCPOPT_NOP){
            len --;
            opt = (tcp_opt*)((char *)opt+1);
            break;
        }
        LOGD(DVPN,"TCP option: %d (%d)\n", opt->kind, opt->length);
        len -= opt->length;
        opt = (tcp_opt*)((char *)opt+opt->length);
    }
}

#if 0
/**
 * 返回包类型
 */
int Tcp::getType() const{
    if (tcplen > 0) {
        if (TCP_FL(tcp_hdr, TH_SYN)) //syn握手包
            return PTYPE_TCP_SYN;
        if (TCP_FL(tcp_hdr, TH_ACK) && datalen > 0) //data包
            return PTYPE_TCP_DATA;
        if (TCP_FL(tcp_hdr, TH_RST)) //rst包
            return PTYPE_TCP_RST;
        if (TCP_FL(tcp_hdr, TH_FIN)) //fin包
            return PTYPE_TCP_FIN;
        if (TCP_FL(tcp_hdr, TH_ACK)) //ack包
            return PTYPE_TCP_ACK;
    }
    return PTYPE_UNKNOW;
}

#endif

Udp::Udp(const char* packet, size_t len){
    if(len < sizeof(udphdr)){
        LOGE("Invalid UDP packet length: %zu bytes\n", len);
        throw 0;
    }
    /* define/compute udp header offset */
    memcpy(&udp_hdr, packet, sizeof(struct udphdr));
    uint16_t udplen = ntohs(udp_hdr.uh_ulen);
    if (udplen < 8) {
        LOGE("Invalid UDP length: %u bytes\n", udplen);
        throw 0;
    }

}


Udp::Udp(uint16_t sport, uint16_t dport) {
    udp_hdr.uh_sport = htons(sport);
    udp_hdr.uh_dport = htons(dport);
    udp_hdr.uh_ulen = htons(sizeof(udphdr));
    udp_hdr.uh_sum = 0;
}


char* Udp::build_packet(const ip* ip_hdr, void* data, size_t& len) {
    assert(data);
    
    len =  sizeof(udphdr) + len;

    udp_hdr.uh_ulen = htons(len);
    udp_hdr.uh_sum = 0;
    char* packet = (char *)p_move(data, -(char)sizeof(udphdr));
    memcpy(packet, &udp_hdr, sizeof(udphdr));

#ifdef UDP_CHECKSUM
    ((udphdr *)packet)->uh_sum = ip_checksum(ip_hdr, IPPROTO_UDP, packet, len);
#endif
    return packet;
}

char * Udp::build_packet(const ip6_hdr* ip_hdr, void* data, size_t& len) {
    assert(data);

    len =  sizeof(udphdr) + len;

    udp_hdr.uh_ulen = htons(len);
    udp_hdr.uh_sum = 0;
    char* packet = (char *)p_move(data, -(char)sizeof(udphdr));
    memcpy(packet, &udp_hdr, sizeof(udphdr));

#ifdef UDP_CHECKSUM
    ((udphdr *)packet)->uh_sum = ip6_checksum(ip_hdr, IPPROTO_UDP, packet, len);
#endif
    return packet;
}



uint16_t Udp::getsport() const{
    return ntohs(udp_hdr.uh_sport);
}

uint16_t Udp::getdport() const{
    return ntohs(udp_hdr.uh_dport);
}


/**
 * 输出udp头
 */
void Udp::print() const{
    LOGD(DVPN, "UDP header:"
    "Src port: %d, "
    "Dst port: %d, "
    "Length: %d, "
    "Checksum: %d\n",

        ntohs(udp_hdr.uh_sport),
        ntohs(udp_hdr.uh_dport),
        ntohs(udp_hdr.uh_ulen),
        ntohs(udp_hdr.uh_sum));
}

size_t Ip::gethdrlen() const {
    switch(type){
    case IPPROTO_ICMP:
        return hdrlen + sizeof(icmphdr);
    case IPPROTO_ICMPV6:
        return hdrlen + sizeof(icmp6_hdr);
    case IPPROTO_TCP:
        return hdrlen + tcp->hdrlen;
    case IPPROTO_UDP:
        return hdrlen + sizeof(udphdr);
    default:
        return hdrlen;
    }
}

uint8_t Ip::gettype() const {
    return type;
}


void Ip::dump() const{
    print();
    switch (type) {
    case IPPROTO_ICMP:
        icmp->print();
        break;
    case IPPROTO_ICMPV6:
        icmp6->print();
        break;
    case IPPROTO_TCP:
        tcp->print();
        break;
    case IPPROTO_UDP:
        udp->print();
        break;
    default:
        break;
    }
}

char* Ip::build_packet(const void* data, size_t &len){
    return build_packet(p_memdup(data, len), len);
}

Ip::~Ip() {
    switch(type){
    case IPPROTO_TCP:
        delete tcp;
        break;
    case IPPROTO_UDP:
        delete udp;
        break;
    case IPPROTO_ICMP:
        delete icmp;
        break;
    case IPPROTO_ICMPV6:
        delete icmp6;
        break;
    default:
        break;
    }
}


std::shared_ptr<Ip> MakeIp(const char* packet, size_t len) {
    const ip* hdr = (const ip*)packet;
    if(hdr->ip_v == IPVERSION){
        return std::shared_ptr<Ip4>(new Ip4(packet, len));
    }
    if(hdr->ip_v == 6){
        return std::shared_ptr<Ip6>(new Ip6(packet, len));
    }
    LOGE("Invalid IP version: %u\n", hdr->ip_v);
    throw 0;
}

std::shared_ptr<Ip> MakeIp(uint8_t type, const sockaddr_un* src, const sockaddr_un* dst) {
    if(src->addr.sa_family == AF_INET){
        return std::shared_ptr<Ip4>(new Ip4(type, src, dst));
    }
    if(src->addr.sa_family == AF_INET6){
        return std::shared_ptr<Ip6>(new Ip6(type, src, dst));
    }
    LOGE("Invalid sa_family: %u\n", src->addr.sa_family);
    throw 0;
}


/**
 * 解析packet，不能带L2的头，ip头+tcp/udp头+data
 */
Ip4::Ip4(const char *packet, size_t len){
    if(len < sizeof(struct ip)){
        LOGE("Invalid IP header length: %zu bytes\n", len);
        throw 0;
    }
    /* define/compute ip header offset */
    memcpy(&hdr, packet, sizeof(struct ip));
    hdrlen = hdr.ip_hl * 4;
    if (hdrlen < 20) {
        LOGE("Invalid IP header length: %u bytes\n", hdrlen);
        throw 0;
    }
    type = hdr.ip_p;

    /* determine protocol */
    switch (type) {
    case IPPROTO_ICMP:
        icmp = new Icmp(packet+hdrlen, len-hdrlen);
        break;
    case IPPROTO_TCP:
        tcp = new Tcp(packet+hdrlen, len-hdrlen);
        break;
    case IPPROTO_UDP:
        udp = new Udp(packet+hdrlen, len-hdrlen);
        break;
    default:
        LOGD(DVPN, "IP(%u) packet size: %u, ip hrdlen: %u.\n", type, ntohs(hdr.ip_len), hdrlen);
        break;
    }
}


Ip4::Ip4(uint8_t type, uint16_t sport, uint16_t dport){
    memset(&hdr, 0, sizeof(hdr));
    hdr.ip_v = 4;
    hdr.ip_hl = 5;
    hdr.ip_tos = 0;
    hdr.ip_len = 0;
    hdr.ip_id = htons(0); /* kernel will fill with random value if 0 */
    hdr.ip_off = 0;
    hdr.ip_ttl = 64;
    hdr.ip_p = type;
    hdr.ip_sum = 0;
    this->type = type;
    switch(type){
    case IPPROTO_ICMP:
        icmp = new Icmp();
        hdr.ip_len = sizeof(ip) + sizeof(icmphdr);
        break;
    case IPPROTO_TCP:
        tcp = new Tcp(sport, dport);
        hdr.ip_len = sizeof(ip) + sizeof(tcphdr);
        break;
    case IPPROTO_UDP:
        udp = new Udp(sport, dport);
        hdr.ip_len = sizeof(ip) + sizeof(udphdr);
        break;
    default:
        throw 0;
    }
}

Ip4::Ip4(uint8_t type, const in_addr* src, uint16_t sport, const in_addr* dst, uint16_t dport):
    Ip4(type, sport, dport) {
    hdr.ip_src = *src;
    hdr.ip_dst = *dst;
}

Ip4::Ip4(uint8_t type, const sockaddr_un* src, const sockaddr_un* dst):
    Ip4(type, &src->addr_in.sin_addr, ntohs(src->addr_in.sin_port),
        &dst->addr_in.sin_addr, ntohs(dst->addr_in.sin_port))
{
}


char* Ip4::build_packet(void* data, size_t &len){
    char* packet;
    switch(type){
    case IPPROTO_ICMP:
        packet = icmp->build_packet(data, len);
        break;
    case IPPROTO_TCP:
        packet = tcp->build_packet(&hdr, data, len);
        break;
    case IPPROTO_UDP:
        packet = udp->build_packet(&hdr, data, len);
        break;
    default:
        assert(0);
    }
    packet = (char *)p_move(packet, -(int)sizeof(ip));
    len += sizeof(ip);

    hdr.ip_len = htons(len);
    hdr.ip_sum = 0;
    memcpy(packet, &hdr, sizeof(ip));

    ((ip*)packet)->ip_sum = htons(checksum16((uint8_t*)packet, sizeof(struct ip)));
    return packet;
}


sockaddr_un Ip4::getsrc() const {
    sockaddr_un  addr;
    memset(&addr, 0, sizeof(addr));
    addr.addr.sa_family = AF_INET;
    addr.addr_in.sin_addr = hdr.ip_src;
    return addr;
}

sockaddr_un Ip4::getdst() const {
    sockaddr_un  addr;
    memset(&addr, 0, sizeof(addr));
    addr.addr.sa_family = AF_INET;
    addr.addr_in.sin_addr = hdr.ip_dst;
    return addr;
}


/**
 * 输出ip头
 */
void Ip4::print() const{
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    LOGD(DVPN,"IP header: "
    "From: %s, "
    "To: %s, "
    "Version: %d, "
    "Length: %d, "
    "Tos: %d, "
    "Totol length: %d, "
    "Pid: %d, "
    "TTL: %d, "
    "Proto: %d, "
    "Checksum: %d\n",
         inet_ntop(AF_INET, &hdr.ip_src, sip, sizeof(sip)),
         inet_ntop(AF_INET, &hdr.ip_dst, dip, sizeof(dip)),
         hdr.ip_v,
         hdr.ip_hl * 4 ,
         hdr.ip_tos,
         ntohs(hdr.ip_len),
         ntohs(hdr.ip_id),
         hdr.ip_ttl,
         hdr.ip_p,
         ntohs(hdr.ip_sum));
}

Ip6::Ip6(const char* packet, size_t len) {
    if(len < sizeof(struct ip6_hdr)){
        LOGE("Invalid IP6 header length: %zu bytes\n", len);
        throw 0;
    }
    /* define/compute ip header offset */
    memcpy(&hdr, packet, sizeof(struct ip6_hdr));
    type = hdr.ip6_nxt;
    ip6_ext* ext_hdr = (ip6_ext*)(packet+sizeof(ip6_hdr));
    while((const char*)ext_hdr - packet < (long)len){
        switch(type){
        case IPPROTO_ICMPV6:
            hdrlen = (const char*)ext_hdr - packet;
            icmp6 = new Icmp6((const char*)ext_hdr, packet+len-(char*)ext_hdr);
            break;
        case IPPROTO_TCP:
            hdrlen = (const char*)ext_hdr - packet;
            tcp = new Tcp((const char*)ext_hdr, packet+len-(char*)ext_hdr);
            break;
        case IPPROTO_UDP:
            hdrlen = (const char*)ext_hdr - packet;
            udp = new Udp((const char*)ext_hdr, packet+len-(char*)ext_hdr);
            break;
        }
        if(icmp6){
            break;
        }
        type = ext_hdr->ip6e_nxt;
        ext_hdr = (ip6_ext*)((char*)(ext_hdr + 1)+ext_hdr->ip6e_len);
    }
}

Ip6::Ip6(uint8_t type, uint16_t sport, uint16_t dport) {
    memset(&hdr, 0, sizeof(hdr));
    hdr.ip6_vfc = 0x60;
    hdr.ip6_nxt = type;
    hdr.ip6_hlim = 64;
    this->type = type;
    switch(type){
    case IPPROTO_ICMPV6:
        icmp6 = new Icmp6();
        hdr.ip6_plen = htons(sizeof(icmp6_hdr));
        break;
    case IPPROTO_TCP:
        tcp = new Tcp(sport, dport);
        hdr.ip6_plen = htons(sizeof(tcphdr));
        break;
    case IPPROTO_UDP:
        udp = new Udp(sport, dport);
        hdr.ip6_plen = htons(sizeof(udphdr));
        break;
    default:
        throw 0;
    }
}

Ip6::Ip6(uint8_t type, const in6_addr* src, uint16_t sport, const in6_addr* dst, uint16_t dport):
    Ip6(type, sport, dport) {
    hdr.ip6_src = *src;
    hdr.ip6_dst = *dst;
}


Ip6::Ip6(uint8_t type, const sockaddr_un* src,  const sockaddr_un* dst):
    Ip6(type, &src->addr_in6.sin6_addr, ntohs(src->addr_in6.sin6_port),
        &dst->addr_in6.sin6_addr, ntohs(dst->addr_in6.sin6_port))
{
}

sockaddr_un Ip6::getdst() const {
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.addr_in6.sin6_family = AF_INET6;
    addr.addr_in6.sin6_addr = hdr.ip6_dst;
    return addr;
}

sockaddr_un Ip6::getsrc() const {
    sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.addr_in6.sin6_family = AF_INET6;
    addr.addr_in6.sin6_addr = hdr.ip6_src;
    return addr;
}

void Ip6::print() const {
    char sip[INET6_ADDRSTRLEN];
    char dip[INET6_ADDRSTRLEN];
    LOGD(DVPN,"IP header: "
    "From: %s, "
    "To: %s, "
    "Version: %d, "
    "TC: %d, "
    "Flow: %d, "
    "payload length: %d, "
    "type: %d, "
    "TTL: %d\n",
         inet_ntop(AF_INET6, &hdr.ip6_src, sip, sizeof(sip)),
         inet_ntop(AF_INET6, &hdr.ip6_dst, dip, sizeof(dip)),
         hdr.ip6_vfc >> 4,
         (ntohl(hdr.ip6_flow) >> 20) & 0xff,
         ntohl(hdr.ip6_flow) & 0xfffff,
         ntohs(hdr.ip6_plen),
         type,
         hdr.ip6_hlim);
}


char* Ip6::build_packet(void* data, size_t& len) {
    char* packet;
    switch(type){
    case IPPROTO_ICMPV6:
        packet = icmp6->build_packet(&hdr, data, len);
        break;
    case IPPROTO_TCP:
        packet = tcp->build_packet(&hdr, data, len);
        break;
    case IPPROTO_UDP:
        packet = udp->build_packet(&hdr, data, len);
        break;
    default:
        assert(0);
    }
    packet = (char *)p_move(packet, -(int)sizeof(ip6_hdr));

    hdr.ip6_plen = htons(len);
    memcpy(packet, &hdr, sizeof(ip6_hdr));
    len += sizeof(ip6_hdr);
    return packet;
}




