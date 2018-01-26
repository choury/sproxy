#include "ip_pack.h"
#include "common.h"
#include "misc/util.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
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

uint16_t Icmp::getid() const
{
    assert(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY);
    return ntohs(icmp_hdr.un.echo.id);
}

uint16_t Icmp::getseq() const
{
    assert(icmp_hdr.type == ICMP_ECHO || icmp_hdr.type == ICMP_ECHOREPLY);
    return ntohs(icmp_hdr.un.echo.sequence);
}



char * Icmp::build_packet(const void* data, size_t& len) {
    assert(len);
    size_t datalen = len;
    len = datalen + sizeof(icmp_hdr);
    char* packet = (char *) p_malloc(len);

    memset(packet, 0, len);
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));

    if(data){
        char *icmpdata = (char *) (packet + sizeof(icmp_hdr));
        memcpy(icmpdata, data, datalen);
    }

    ((icmp *)packet)->icmp_cksum = htons(checksum16((uint8_t*)packet, len));
    return packet;
}

char * Icmp::build_packet(void* data, size_t& len) {
    assert(data);
    len = len + sizeof(icmp_hdr);
    char* packet = (char *)p_move(data, -(char)sizeof(icmp_hdr));
    icmp_hdr.checksum = 0;
    memcpy(packet, &icmp_hdr, sizeof(icmp_hdr));
    ((icmp *)packet)->icmp_cksum = htons(checksum16((uint8_t*) packet, len));
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
    memset(&tcp_hdr, 0, sizeof(tcphdr));
    
    tcp_hdr.source = htons(sport);
    tcp_hdr.dest = htons(dport);

    tcp_hdr.doff = 5;
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
    ((uint8_t *)&tcp_hdr)[13] = flag;
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
    t->length = TCPOLEN_TIMESTAMP;

    struct timeval now;
    if (gettimeofday(&now, NULL) < 0)
        LOGE("Couldn't get time of day:%s\n", strerror(errno));
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

    char* packet = (char *) p_malloc(len + sizeof(pseudo_hdr));
    memset(packet, 0, len);

    tcp_hdr.doff = (sizeof(tcphdr) + tcpoptlen) >> 2;
    tcp_hdr.check = 0;

    char* packet_end = packet + sizeof(pseudo_hdr);
    memcpy(packet_end, &tcp_hdr, sizeof(tcphdr));

    packet_end += sizeof(tcphdr);

    if (tcpoptlen > 0){
        memcpy(packet_end, tcpopt, tcpoptlen); //copy tcp header option to packet
        packet_end += tcpoptlen;
    }

    if(data){
        memcpy(packet_end, data, datalen); // copy tcp data to packet
        packet_end += datalen;
    }

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *)packet;
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_TCP;
    phdr->len = htons(len);
    /* tcp checksum */
    ((tcphdr *)(packet+sizeof(pseudo_hdr)))->check = htons(checksum16((uint8_t*)packet, packet_end - packet));
    return (char *)p_move(packet, sizeof(pseudo_hdr));
}

char * Tcp::build_packet(void* data, size_t& len) {
    if (tcpoptlen % 4) {
        LOGE("TCP option length must be divisible by 4.\n");
        return 0;
    }
    assert(data);

    len = sizeof(tcphdr) + tcpoptlen + len;

    char* packet = (char *) p_move(data, -(char)(sizeof(pseudo_hdr)+sizeof(tcphdr)+tcpoptlen));

    tcp_hdr.doff = (sizeof(tcphdr) + tcpoptlen) >> 2;
    tcp_hdr.check = 0;
    memcpy(packet + sizeof(pseudo_hdr), &tcp_hdr, sizeof(tcphdr));

    if (tcpoptlen > 0)
        memcpy(packet + sizeof(pseudo_hdr) + sizeof(tcphdr), tcpopt, tcpoptlen); //copy tcp header option to packet

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *)packet;
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_TCP;
    phdr->len = htons(len);
    /* tcp checksum */
    ((tcphdr *)(packet+sizeof(pseudo_hdr)))->check = htons(checksum16((uint8_t*)packet, len  + sizeof(pseudo_hdr)));
    return (char *)p_move(packet, sizeof(pseudo_hdr));
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

uint16_t Tcp::getwindow() const {
    return ntohs(tcp_hdr.window);
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

         ntohs(tcp_hdr.source),
         ntohs(tcp_hdr.dest),
         ntohl(tcp_hdr.seq),
         ntohl(tcp_hdr.ack_seq),
         tcp_hdr.doff * 4,
         tcp_hdr.fin,
         tcp_hdr.syn,
         tcp_hdr.rst,
         tcp_hdr.psh,
         tcp_hdr.ack,
         tcp_hdr.urg,
         ntohs(tcp_hdr.window),
         ntohs(tcp_hdr.check),
         ntohs(tcp_hdr.urg_ptr));
    
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
    udp_hdr.source = htons(sport);
    udp_hdr.dest = htons(dport);
    udp_hdr.len = htons(sizeof(udphdr));
    udp_hdr.check = 0;
}


/**
 * 组建udp/ip回包
 */
char* Udp::build_packet(const void* data, size_t& len) {
    size_t datalen = data?len:0;
    len =  sizeof(udphdr) + datalen;

    char* packet = (char *) p_malloc(len + sizeof(pseudo_hdr));
    memset(packet, 0, len);

    char* packet_end = packet + sizeof(pseudo_hdr);

    udp_hdr.len = htons(len);
    udp_hdr.check = 0;
    memcpy(packet_end, &udp_hdr, sizeof(udphdr));
    packet_end += sizeof(udphdr);

    if(data){
        memcpy(packet_end, data, datalen); // copy tcp data to packet
        packet_end += datalen;
    }

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *)packet;
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_UDP;
    phdr->len = htons(len);
    /* udp checksum */
    ((udphdr*)(packet+sizeof(pseudo_hdr)))->check = htons(checksum16((uint8_t*)packet, packet_end - packet));

    return (char*)p_move(packet, sizeof(pseudo_hdr));
}

char* Udp::build_packet(void* data, size_t& len) {
    assert(data);
    
    len =  sizeof(udphdr) + len;
    char* packet = (char *) p_move(data, -(char)(sizeof(udphdr)+sizeof(pseudo_hdr)));

    udp_hdr.len = htons(len);
    udp_hdr.check = 0;
    memcpy(packet+sizeof(pseudo_hdr), &udp_hdr, sizeof(udphdr));

    /* pseudo header used for checksumming */
    pseudo_hdr *phdr = (struct pseudo_hdr *)packet;
    phdr->src = ip_hdr->ip_src.s_addr;
    phdr->dst = ip_hdr->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_UDP;
    phdr->len = htons(len);
    /* udp checksum */
    ((udphdr*)(packet+sizeof(pseudo_hdr)))->check = htons(checksum16((uint8_t*) packet, len + sizeof(pseudo_hdr)));

    return (char*)p_move(packet, sizeof(pseudo_hdr));
}


uint16_t Udp::getsport() const{
    return ntohs(udp_hdr.source);
}

uint16_t Udp::getdport() const{
    return ntohs(udp_hdr.dest);
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

        ntohs(udp_hdr.source),
        ntohs(udp_hdr.dest),
        ntohs(udp_hdr.len),
        ntohs(udp_hdr.check));
}




/**
 * 解析packet，不能带L2的头，ip头+tcp/udp头+data
 */
Ip::Ip(const char *packet, size_t len){
    if(len < sizeof(struct ip)){
        LOGE("Invalid IP header length: %zu bytes\n", len);
        throw 0;
    }
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
            break;
        case IPPROTO_TCP:
            tcp = new Tcp(&ip_hdr, packet+hdrlen, len-hdrlen);
            break;
        case IPPROTO_UDP:
            udp = new Udp(&ip_hdr, packet+hdrlen, len-hdrlen);
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
        ip_hdr.ip_len = sizeof(ip) + sizeof(icmphdr);
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

Ip::Ip(uint8_t type, const sockaddr_un* src, const sockaddr_un* dst):
    Ip(type, ntohs(src->addr_in.sin_port), ntohs(dst->addr_in.sin_port)) {
    ip_hdr.ip_src = src->addr_in.sin_addr;
    ip_hdr.ip_dst = dst->addr_in.sin_addr;
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
    char* packet;
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
    default:
        packet = (char *)p_malloc(len);
        memcpy(packet, data, len);
        break;
    }
    packet = (char *)p_move(packet, -(int)sizeof(ip));
    len += sizeof(ip);
    ip_hdr.ip_len = htons(len);
    ip_hdr.ip_sum = 0;
    memcpy(packet, &ip_hdr, sizeof(ip));

    ((ip*)packet)->ip_sum = htons(checksum16((uint8_t*)packet, sizeof(struct ip)));
    return packet;
}

char* Ip::build_packet(void* data, size_t &len){
    char* packet;
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
    default:
        packet = (char *)data;
        break;
    }
    packet = (char *)p_move(packet, -(int)sizeof(ip));
    len += sizeof(ip);

    ip_hdr.ip_len = htons(len);
    ip_hdr.ip_sum = 0;
    memcpy(packet, &ip_hdr, sizeof(ip));

    ((ip*)packet)->ip_sum = htons(checksum16((uint8_t*)packet, sizeof(struct ip)));
    return packet;
}

size_t Ip::gethdrlen() const {
    switch(gettype()){
    case IPPROTO_ICMP:
        return hdrlen + sizeof(icmphdr);
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

uint16_t Ip::getid() const
{
    return ntohs(ip_hdr.ip_id);
}

uint16_t Ip::getflag() const
{
    return ntohs(ip_hdr.ip_off) & (~IP_OFFMASK);
}

const in_addr * Ip::getsrc() const {
    return &ip_hdr.ip_src;
}

const in_addr * Ip::getdst() const {
    return &ip_hdr.ip_dst;
}

Ip* Ip::setid(uint16_t id){
    ip_hdr.ip_id = htons(id);
    return this;
}

Ip* Ip::setflag(uint16_t flag)
{
    ip_hdr.ip_off |= htons(flag & (~IP_OFFMASK));
    return this;
}


/**
 * 输出ip头
 */
void Ip::print() const{
    char sip[INET_ADDRSTRLEN] __attribute__((unused));
    char dip[INET_ADDRSTRLEN] __attribute__((unused));
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

