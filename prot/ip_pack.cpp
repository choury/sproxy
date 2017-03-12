#include "ip_pack.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <assert.h>


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
} __attribute__((packed)) pseudo_hdr;

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


/**
  * calculate checksum in ip/tcp header
  */
static uint16_t checksum_comp(uint16_t *addr, int len) {
    long sum = 0;
    uint16_t checksum;
    int count = len;
    uint16_t temp;

    while (count > 1) {
        temp = *addr++;
        sum += temp;
        count -= 2;
    }
    if (count > 0)
        sum += *(char *) addr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    checksum = ~sum;
    return checksum;
}


Icmp::Icmp() {
    memset(&icmp_hdr, 0, sizeof(icmphdr));
}

Icmp::Icmp(const char* packet, size_t len){
    if(len < sizeof(icmphdr)){
        LOGE("Invalid ICMP header length: %zu bytes\n", len);
        throw 0;
    }
    memcpy(&icmp_hdr, packet, sizeof(icmphdr));
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


char * Icmp::build_packet(const void* data, size_t& len) {
    size_t datalen = data?len:0;
    len = datalen + sizeof(icmphdr);
    char* packet = (char *) p_malloc(len);

    memset(packet, 0, len);
    memcpy(packet, &icmp_hdr, sizeof(icmphdr));

    if(data){
        char *icmpdata = (char *) (packet + sizeof(icmphdr));
        memcpy(icmpdata, data, datalen);
    }

    ((icmphdr *)packet)->checksum = checksum_comp((unsigned short *) packet, len);
    return packet;
}


Tcp::Tcp(const ip* ip_hdr, const char* packet, size_t len):ip_hdr(ip_hdr){
    memcpy(&tcp_hdr, packet, sizeof(struct tcphdr));
    hdrlen = tcp_hdr.doff * 4;
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

Tcp::Tcp(const ip* ip_hdr, uint16_t sport, uint16_t dport):ip_hdr(ip_hdr){
    tcp_hdr.source = htons(sport);
    tcp_hdr.dest = htons(dport);

    tcp_hdr.seq = 0;
    tcp_hdr.ack_seq = 0;
    tcp_hdr.res1 = 0;
    tcp_hdr.doff = 5 + (tcpoptlen / 4);
    tcp_hdr.th_flags = 0;
    tcp_hdr.window = 0;
    tcp_hdr.check = 0;
    tcp_hdr.urg_ptr = 0;
}

Tcp::~Tcp() {
    free(tcpopt);
}



Tcp * Tcp::setseq(uint32_t seq) {
    tcp_hdr.seq = htonl(seq);
    return this;
}


Tcp * Tcp::setack(uint32_t ack) {
    tcp_hdr.ack_seq = htonl(ack);
    return this;
}

Tcp * Tcp::setwindow(uint32_t window) {
    if(window > 65535){
        tcp_hdr.window = htons(65535);
    }else{
        tcp_hdr.window = htons(window);
    }
    return this;
}

Tcp * Tcp::setflag(uint8_t flag) {
    tcp_hdr.th_flags = flag;
    return this;
}


/**
 * Build TCP timestamp option
 * tcpopt points to possibly already existing TCP options
 * so inspect current TCP option length (tcpopt_len)
 */
Tcp* Tcp::settimestamp(uint32_t tsval, uint32_t tsecr) {

    if (tcpopt) {
        tcpopt = (char *) realloc(tcpopt, tcpoptlen + sizeof(tcp_timestamp));
    } else{
        assert(tcpoptlen == 0);
        tcpopt = (char *) malloc(sizeof(tcp_timestamp));
    }

    tcp_timestamp *t = (tcp_timestamp *)(tcpopt+tcpoptlen);

    memset(t, TCPOPT_NOP, sizeof(tcp_timestamp));
    t->kind = TCPOPT_TIMESTAMP;
    t->length = 10;

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
        LOGE("Couldn't get time of day:%m\n");
    t->tsval = htonl((tsval) ? tsval : (uint32_t) now.tv_sec);
    t->tsecr = htonl((tsecr) ? tsecr : 0);

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
    t->length = 4;
    t->mss = htons(mss);

    tcpoptlen += sizeof(tcp_mss);

    return this;
}

/**
 * 组建tcp/ip回包，
 */
char* Tcp::build_packet(const void* data, size_t& len) {

    if (tcpoptlen % 4) {
        LOGE("TCP option length must be divisible by 4.\n");
        return 0;
    }

    size_t datalen = data?len:0;
    len = sizeof(tcphdr) + tcpoptlen + datalen;
    /* fake length to account for 16bit word padding chksum */
    unsigned int chklen;
    if (len % 2)
        chklen = len + 1;
    else
        chklen = len;

    char* packet = (char *) p_malloc(chklen + sizeof(pseudo_hdr));

    memset(packet, 0, chklen);
    memcpy(packet, &tcp_hdr, sizeof(tcphdr));

    if (tcpoptlen > 0)
        memcpy(packet + sizeof(ip) + sizeof(tcphdr), tcpopt, tcpoptlen); //copy tcp header option to packet

    if(data){
        char *tcpdata = (char *) (packet + sizeof(tcphdr) + tcpoptlen);
        memcpy(tcpdata, data, datalen); // copy tcp data to packet
    }

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *) ((char *) packet + chklen);
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_TCP;
    phdr->len = htons((tcp_hdr.doff * 4) + datalen);
    /* tcp checksum */
    ((tcphdr *)packet)->check = checksum_comp((unsigned short *) packet, chklen  + sizeof(*phdr));
    return packet;
}



/**
 * Parse TCP options and get timestamp if it exists.
 * Return 1 if timestamp valid, 0 for failure
 */
int Tcp::gettimestamp(uint32_t *tsval, uint32_t *tsecr) const{
    char *p;
    unsigned int op;
    unsigned int oplen;
    unsigned int len = 0;

    if (!tsval || !tsecr)
        return 0;

    p = (char *)tcpopt;
    len = 4 * tcp_hdr.th_off - sizeof(tcphdr);

    while (len > 0 && *p != TCPOPT_EOL) {
        op = *p++;
        if (op == TCPOPT_EOL)
            break;
        if (op == TCPOPT_NOP) {
            len--;
            continue;
        }
        oplen = *p++;
        if (oplen < 2)
            break;
        if (oplen > len)
            break; /* not enough space */
        if (op == TCPOPT_TIMESTAMP && oplen == 10) {
            /* legitimate timestamp option */
            if (tsval) {
                memcpy((char *) tsval, p, 4);
                *tsval = ntohl(*tsval);
            }
            p += 4;
            if (tsecr) {
                memcpy((char *) tsecr, p, 4);
                *tsecr = ntohl(*tsecr);
            }
            return 1;
        }
        len -= oplen;
        p += oplen - 2;
    }
    *tsval = 0;
    *tsecr = 0;
    return 0;
}

uint32_t Tcp::getseq() const {
    return ntohl(tcp_hdr.seq);
}

uint32_t Tcp::getack() const {
    return ntohl(tcp_hdr.ack_seq);
}

uint16_t Tcp::getsport() const {
    return ntohs(tcp_hdr.source);
}

uint16_t Tcp::getdport() const {
    return ntohs(tcp_hdr.dest);
}

uint8_t Tcp::getflag() const {
    return tcp_hdr.th_flags;
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
    "Flags: %d, "
    "FIN= %d, "
    "SYN= %d, "
    "RST= %d, "
    "PSH= %d, "
    "ACK= %d, "
    "URG= %d, "
    "Window size: %d, "
    "Checksum: %d, "
    "Urgent point: %d\n",

         ntohs(tcp_hdr.source),
         ntohs(tcp_hdr.dest),
         ntohl(tcp_hdr.seq),
         ntohl(tcp_hdr.ack_seq),
         tcp_hdr.doff * 4,
         tcp_hdr.th_flags,
         tcp_hdr.fin,
         tcp_hdr.syn,
         tcp_hdr.rst,
         tcp_hdr.psh,
         tcp_hdr.ack,
         tcp_hdr.urg,
         ntohs(tcp_hdr.window),
         ntohs(tcp_hdr.check),
         ntohs(tcp_hdr.urg_ptr));
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

Udp::Udp(const ip* ip_hdr, const char* packet, size_t len):ip_hdr(ip_hdr){
    if(len < sizeof(udphdr)){
        LOGE("Invalid UDP packet length: %zu bytes\n", len);
        throw 0;
    }
    /* define/compute udp header offset */
    memcpy(&udp_hdr, packet, sizeof(struct udphdr));
    uint16_t udplen = ntohs(udp_hdr.len);
    if (udplen < 8) {
        LOGE("Invalid UDP length: %u bytes\n", udplen);
        throw 0;
    }

}


Udp::Udp(const ip* ip_hdr, uint16_t sport, uint16_t dport):ip_hdr(ip_hdr) {
    udp_hdr.uh_sport = htons(sport);
    udp_hdr.uh_dport = htons(dport);
    udp_hdr.uh_ulen = htons(sizeof(udphdr));
    udp_hdr.uh_sum = 0;
}


/**
 * 组建udp/ip回包
 */
char* Udp::build_packet(const void* data, size_t& len) {
    /* fake length to account for 16bit word padding chksum */
    unsigned int chklen;

    size_t datalen = data?len:0;
    len =  sizeof(udphdr) + datalen;
    if (len % 2)
        chklen = len + 1;
    else
        chklen = len;

    udp_hdr.uh_ulen = htons(len);
    char* packet = (char *) p_malloc(chklen + sizeof(pseudo_hdr));
    memset(packet, 0, chklen);
    memcpy(packet, &udp_hdr, sizeof(udphdr));

    if(data){
        char *udpdata = (char *) (packet + sizeof(udphdr));
        memcpy(udpdata, data, datalen); // copy tcp data to packet
    }

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *) ((char *) packet + chklen);
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_UDP;
    phdr->len = htons(sizeof(udphdr) + datalen);
    /* udp checksum */
    ((udphdr*)packet)->uh_sum = checksum_comp((unsigned short *) packet, chklen + sizeof(*phdr));

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




/**
 * 解析packet，不能带L2的头，ip头+tcp/udp头+data
 */
Ip::Ip(const char *packet, size_t len){

    /* define/compute ip header offset */
    memcpy(&ip_hdr, packet, sizeof(struct ip));
    hdrlen = ip_hdr.ip_hl * 4;
    if (hdrlen < 20) {
        LOGE("Invalid IP header length: %u bytes\n", hdrlen);
        throw 0;
    }

    /* determine protocol */
    switch (gettype()) {
        case IPPROTO_ICMP:
            icmp = new Icmp(packet+hdrlen, len-hdrlen);
            LOGD(DVPN, "IP(ICMP) packet size: %u, ip hrdlen: %u.\n", ntohs(ip_hdr.ip_len), hdrlen);
            break;
        case IPPROTO_TCP:
            tcp = new Tcp(&ip_hdr, packet+hdrlen, len-hdrlen);
            LOGD(DVPN, "IP(TCP) packet size: %u, ip hrdlen: %u tcp hdrlen:%u.\n", ntohs(ip_hdr.ip_len), hdrlen, tcp->hdrlen);
            break;
        case IPPROTO_UDP:
            udp = new Udp(&ip_hdr, packet+hdrlen, len-hdrlen);
            LOGD(DVPN, "IP(UDP) packet size: %u, ip hrdlen: %u\n", ntohs(ip_hdr.ip_len), hdrlen);
            break;
        default:
            LOGD(DVPN, "IP(%u) packet size: %u, ip hrdlen: %u.\n", gettype(), ntohs(ip_hdr.ip_len), hdrlen);
            break;
    }
}


Ip::Ip(uint8_t type, uint16_t sport, uint16_t dport){
    ip_hdr.ip_v = 4;
    ip_hdr.ip_hl = 5;
    ip_hdr.ip_tos = 0;
    ip_hdr.ip_len = 0;
    ip_hdr.ip_id = htons(0); /* kernel will fill with random value if 0 */
    ip_hdr.ip_off = 0;
    ip_hdr.ip_ttl = 64;
    ip_hdr.ip_p = type;
    ip_hdr.ip_sum = 0;
    switch(type){
    case IPPROTO_ICMP:
        icmp = new Icmp();
        ip_hdr.ip_len = sizeof(ip) + sizeof(icmp);
        break;
    case IPPROTO_TCP:
        tcp = new Tcp(&ip_hdr, sport, dport);
        ip_hdr.ip_len = sizeof(ip) + sizeof(tcphdr);
        break;
    case IPPROTO_UDP:
        udp = new Udp(&ip_hdr, sport, dport);
        ip_hdr.ip_len = sizeof(ip) + sizeof(udphdr);
        break;
    default:
        throw 0;
    }
}

Ip::Ip(uint8_t type, const in_addr* src, uint16_t sport, const in_addr* dst, uint16_t dport):
    Ip(type, sport, dport) {
    ip_hdr.ip_src = *src;
    ip_hdr.ip_dst = *dst;
}

Ip::Ip(uint8_t type, const char* src, uint16_t sport, const char* dst, uint16_t dport):
    Ip(type, sport, dport) {
    inet_pton(AF_INET, src, &ip_hdr.ip_src);
    inet_pton(AF_INET, dst, &ip_hdr.ip_dst);
}


Ip::~Ip(){
    switch(gettype()){
    case IPPROTO_TCP:
        delete tcp;
        break;
    case IPPROTO_UDP:
        delete udp;
        break;
    case IPPROTO_ICMP:
        delete icmp;
        break;
    default:
        break;
    }
}


char* Ip::build_packet(const void* data, size_t &len){
    char* packet = nullptr;
    switch(gettype()){
    case IPPROTO_ICMP:
        packet = icmp->build_packet(data, len);
        break;
    case IPPROTO_TCP:
        packet = tcp->build_packet(data, len);
        break;
    case IPPROTO_UDP:
        packet = udp->build_packet(data, len);
        break;
    }
    packet = (char *)p_move(packet, -(int)sizeof(ip));
    len += sizeof(ip);
    ip_hdr.ip_len = htons(len);
    memcpy(packet, &ip_hdr, sizeof(ip));

    ((ip*)packet)->ip_sum = checksum_comp((unsigned short *)packet, sizeof(struct ip));
    return packet;
}

size_t Ip::gethdrlen() const {
    switch(gettype()){
    case IPPROTO_ICMP:
        return hdrlen + sizeof(icmp);
    case IPPROTO_TCP:
        return hdrlen + tcp->hdrlen;
    case IPPROTO_UDP:
        return hdrlen + sizeof(udphdr);
    default:
        return hdrlen;
    }
}

uint8_t Ip::gettype() const
{
    return ip_hdr.ip_p;
}

const in_addr * Ip::getsrc() const {
    return &ip_hdr.ip_src;
}

const in_addr * Ip::getdst() const {
    return &ip_hdr.ip_dst;
}

/**
 * 输出ip头
 */
void Ip::print() const{
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

         inet_ntop(AF_INET, &ip_hdr.ip_src, sip, sizeof(sip)),
         inet_ntop(AF_INET, &ip_hdr.ip_dst, dip, sizeof(dip)),
         ip_hdr.ip_v,
         ip_hdr.ip_hl * 4 ,
         ip_hdr.ip_tos,
         ntohs(ip_hdr.ip_len),
         ntohs(ip_hdr.ip_id),
         ip_hdr.ip_ttl,
         ip_hdr.ip_p,
         ntohs(ip_hdr.ip_sum));

    switch (gettype()) {
        case IPPROTO_ICMP:
            icmp->print();
            break;
        case IPPROTO_TCP:
            tcp->print();
            break;
        case IPPROTO_UDP:
            udp->print();
            break;
        default:
            LOGD(DVPN, "unsopported protol.\n");
            break;
    }
}

