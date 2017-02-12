#include "ip_packet.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>


/**
 * Build TCP timestamp option
 * tcpopt points to possibly already existing TCP options
 * so inspect current TCP option length (tcpopt_len)
 */
char* build_timestamp(char **tcpopt, unsigned int *tcpopt_len,
                           uint32_t tsval, uint32_t tsecr) {
    struct timeval now;
    tcp_timestamp t;
    char *opt = NULL;

    if (*tcpopt_len) {
        opt = (char *) realloc(*tcpopt, *tcpopt_len + sizeof(t));
        *tcpopt = opt;
        opt += *tcpopt_len;
    } else
        *tcpopt = (char *) malloc(sizeof(t));

    memset(&t, TCPOPT_NOP, sizeof(t));
    t.kind = TCPOPT_TIMESTAMP;
    t.length = 10;
    if (gettimeofday(&now, NULL) < 0)
        LOGE("Couldn't get time of day:%m\n");
    t.tsval = htonl((tsval) ? tsval : (uint32_t) now.tv_sec);
    t.tsecr = htonl((tsecr) ? tsecr : 0);

    if (*tcpopt_len)
        memcpy(opt, &t, sizeof(t));
    else
        memcpy(*tcpopt, &t, sizeof(t));

    *tcpopt_len += sizeof(t);

    return *tcpopt;
}

/**
 * Build TCP Maximum Segment Size option
 */
char* build_mss(char **tcpopt, unsigned int *tcpopt_len, uint16_t mss) {
    struct tcp_mss t;
    char *opt;

    if (*tcpopt_len) {
        opt = (char *) realloc(*tcpopt, *tcpopt_len + sizeof(t));
        *tcpopt = opt;
        opt += *tcpopt_len;
    } else
        *tcpopt = (char *) malloc(sizeof(t));

    memset(&t, TCPOPT_NOP, sizeof(t));
    t.kind = TCPOPT_MAXSEG;
    t.length = 4;
    t.mss = htons(mss);

    if (*tcpopt_len)
        memcpy(opt, &t, sizeof(t));
    else
        memcpy(*tcpopt, &t, sizeof(t));

    *tcpopt_len += sizeof(t);
    return *tcpopt;
}

/**
 * Parse TCP options and get timestamp if it exists.
 * Return 1 if timestamp valid, 0 for failure
 */
int get_timestamp(const struct tcphdr *tcp, uint32_t *tsval, uint32_t *tsecr) {
    char *p;
    unsigned int op;
    unsigned int oplen;
    unsigned int len = 0;

    if (!tsval || !tsecr)
        return 0;

    p = ((char *) tcp) + sizeof(*tcp);
    len = 4 * tcp->th_off - sizeof(*tcp);

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

/* parse packet */
static int parse_tcp_packet(struct ip_packet* pac, char *packet_buf);
static int parse_udp_packet(struct ip_packet* pac, char *packet_buf);


/**
 * 解析packet，不能带L2的头，ip头+tcp/udp头+data
 */
int parse_ip_packet(struct ip_packet* pac, char *packet_buf) {
    pac->packet = packet_buf;

    /* define/compute ip header offset */
    pac->ip = (struct ip *) (packet_buf + SIZE_ETHERNET);
    pac->iplen = pac->ip->ip_hl * 4;
    LOGD(DVPN, "IP header size %d.", pac->iplen);
    if (pac->iplen < 20) {
        LOGE("** Invalid IP header length: %u bytes", pac->iplen);
        return -1;
    }

    /* determine protocol */
    switch (pac->ip->ip_p) {
        case IPPROTO_TCP:
            LOGD(DVPN, "Protocol: TCP");
            return parse_tcp_packet(pac, packet_buf);
        case IPPROTO_UDP:
            LOGD(DVPN, "Protocol: UDP");
            return parse_udp_packet(pac, packet_buf);
        case IPPROTO_ICMP:
            LOGE("Protocol: ICMP");
            return 0;
        case IPPROTO_IP:
            LOGE("Protocol: IP");
            return 0;
        default:
            LOGE("** Protocol: unknown");
            return -2;
    }
    return 0;
}

/**
 * 解析TCP层，必需先解出IP层，否则出错
 */
int parse_tcp_packet(struct ip_packet* pac, char *packet_buf) {
    /* define/compute tcp header offset */
    pac->tcp = (struct tcphdr *) (packet_buf + SIZE_ETHERNET + pac->iplen);
    pac->tcplen = pac->tcp->th_off * 4;
    LOGD(DVPN, "TCP header size %d.", pac->tcplen);
    if (pac->tcplen < 20) {
        LOGE("** Invalid TCP header length: %u bytes", pac->tcplen);
        return -3;
    }

    /* define/compute tcp payload (segment) offset */
    pac->data = (char *) (packet_buf + SIZE_ETHERNET + pac->iplen + pac->tcplen);

    /* compute tcp payload (segment) size */
    pac->datalen = ntohs(pac->ip->ip_len) - (pac->iplen + pac->tcplen);
    LOGD(DVPN, "TCP data payload size %d.", pac->datalen);

    return 0;
}

/**
 * 解析UDP层，必需先解出IP层，否则出错
 */
int parse_udp_packet(struct ip_packet* pac, char *packet_buf) {
    /* define/compute udp header offset */
    pac->udp = (udp_hdr *) (packet_buf + SIZE_ETHERNET + pac->iplen);
    pac->udplen = ntohs(pac->udp->uh_ulen);
    LOGD(DVPN, "UDP size %d.", pac->udplen);
    if (pac->udplen < 8) {
        LOGE("** Invalid UDP length: %u bytes", pac->udplen);
        return -6;
    }

    /* define/compute tcp payload (segment) offset */
    pac->data = (char *) (packet_buf + SIZE_ETHERNET + pac->iplen + SIZE_UDP_HEADER);

    /* compute tcp payload (segment) size */
    pac->datalen = ntohs(pac->ip->ip_len) - (pac->iplen + SIZE_UDP_HEADER);
    LOGD(DVPN, "UDP data payload size %d.", pac->datalen);

    return 0;
}

/**
 * 输出ip头
 */
void print_ip_header(const struct ip_packet *pac){
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

         inet_ntoa(pac->ip->ip_src),
         inet_ntoa(pac->ip->ip_dst),
         pac->ip->ip_v,
         pac->ip->ip_hl * 4 ,
         pac->ip->ip_tos,
         ntohs(pac->ip->ip_len),
         ntohs(pac->ip->ip_id),
         pac->ip->ip_ttl,
         pac->ip->ip_p,
         ntohs(pac->ip->ip_sum));
}

/**
 * 输出tcp头
 */
void print_tcp_header(const struct ip_packet *pac){
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

        ntohs(pac->tcp->th_sport),
        ntohs(pac->tcp->th_dport),
        ntohl(pac->tcp->th_seq),
        ntohl(pac->tcp->th_ack),
        pac->tcp->th_off * 4,
        pac->tcp->th_flags,
        TCP_FL(pac->tcp, TH_FIN),
        TCP_FL(pac->tcp, TH_SYN),
        TCP_FL(pac->tcp, TH_RST),
        TCP_FL(pac->tcp, TH_PUSH),
        TCP_FL(pac->tcp, TH_ACK),
        TCP_FL(pac->tcp, TH_URG),
        ntohs(pac->tcp->th_win),
        ntohs(pac->tcp->th_sum),
        ntohs(pac->tcp->th_urp));
}

/**
 * 输出udp头
 */
void print_udp_header(const struct ip_packet* pac){
    LOGD(DVPN, "UDP header:"
    "Src port: %d, "
    "Dst port: %d, "
    "Length: %d, "
    "Checksum: %d, ",

        ntohs(pac->udp->uh_sport),
        ntohs(pac->udp->uh_dport),
        ntohs(pac->udp->uh_ulen),
        ntohs(pac->udp->uh_sum));
}

/**
 * 返回包类型
 */
int getPacketType(const struct ip_packet* pac) {
    if (pac->tcplen > 0) {
        if (TCP_FL(pac->tcp, TH_SYN)) //syn握手包
            return PTYPE_TCP_SYN;
        if (TCP_FL(pac->tcp, TH_ACK) && pac->datalen > 0) //data包
            return PTYPE_TCP_DATA;
        if (TCP_FL(pac->tcp, TH_RST)) //rst包
            return PTYPE_TCP_RST;
        if (TCP_FL(pac->tcp, TH_FIN)) //fin包
            return PTYPE_TCP_FIN;
        if (TCP_FL(pac->tcp, TH_ACK)) //ack包
            return PTYPE_TCP_ACK;
    }
    return PTYPE_UNKNOW;
}

/**
  * calculate checksum in ip/tcp header
  */
uint16_t checksum_comp(uint16_t *addr, int len) {
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

/**
 * 组建tcp/ip回包，
 * 如果是data回包，传入不为空的tcp data，flag为TH_ACK|TH_PUSH，且将tcpoptlen至为0
 * 如果是ack回包，传入空的tcp data，flag为TH_ACK
 * 如果是syn回包，传入空的tcp data，flag为TH_ACK|TH_SYN
 */
char* build_tcpip_packet(const struct ip_packet* pac,
                           uint16_t window, uint8_t flags,
                           size_t* packetlen) {
    char *packet;
    struct ip *iplocal;
    struct tcphdr *tcplocal;
    pseudo_hdr *phdr;
    char *tcpdata;
    /* fake length to account for 16bit word padding chksum */
    unsigned int chklen;
    uint16_t ipid = 0;
    uint8_t ttl = 64;

    if (pac->tcpoptlen % 4) {
        LOGE("** TCP option length must be divisible by 4.");
        return 0;
    }

    *packetlen = sizeof(ip_hdr) + sizeof(tcp_hdr) + pac->tcpoptlen + pac->datalen;
    LOGD(DVPN, "packetlen %zd, datalen %d.", *packetlen, pac->datalen);
    if (*packetlen % 2)
        chklen = *packetlen + 1;
    else
        chklen = *packetlen;

    packet = (char *) p_malloc(chklen + sizeof(*phdr));

    iplocal = (struct ip *) packet;
    tcplocal = (struct tcphdr *) ((char *) iplocal + sizeof(ip_hdr));
    tcpdata = (char *) (packet + sizeof(ip_hdr) + sizeof(tcp_hdr) + pac->tcpoptlen);

    memset(packet, 0, chklen);

    iplocal->ip_v = 4;
    iplocal->ip_hl = 5;
    iplocal->ip_tos = 0;
    iplocal->ip_len = htons(*packetlen); /* must be in host byte order for FreeBSD */
    iplocal->ip_id = htons(ipid); /* kernel will fill with random value if 0 */
    iplocal->ip_off = 0;
    iplocal->ip_ttl = ttl;
    iplocal->ip_p = IPPROTO_TCP;
    iplocal->ip_src.s_addr = pac->ip->ip_src.s_addr;
    iplocal->ip_dst.s_addr = pac->ip->ip_dst.s_addr;
    iplocal->ip_sum = 0;
    iplocal->ip_sum = checksum_comp((unsigned short *) iplocal, sizeof(struct ip));

    tcplocal->th_sport = pac->tcp->th_sport;
    tcplocal->th_dport = pac->tcp->th_dport;

    tcplocal->th_seq = pac->tcp->th_ack;
    tcplocal->th_ack = pac->tcp->th_seq;
    tcplocal->th_x2 = 0;
    tcplocal->th_off = 5 + (pac->tcpoptlen / 4);
    tcplocal->th_flags = flags;
    tcplocal->th_win = htons(window);
    tcplocal->th_urp = 0;
    tcplocal->th_sum = 0;

    //memcpy(packet, (char *)ip, sizeof(*ip)); //copy ip header to packet
    //memcpy(packet + sizeof(*ip), (char *)tcp, sizeof(*tcp)); //copy tcp header to packet
    //ip = (struct ip *)packet; //pointer ip change to new packet
    //tcp = (struct tcphdr *) ((char *)ip + sizeof(*ip)); //pointer tcp change to new packet, need to calculate checksum bellow
    if (pac->tcpoptlen > 0)
        memcpy(packet + sizeof(ip_hdr) + sizeof(tcp_hdr), pac->tcpopt,
               pac->tcpoptlen); //copy tcp header option to packet
    memcpy(tcpdata, pac->data, pac->datalen); // copy tcp data to packet

    /* pseudo header used for checksumming */
    phdr = (struct pseudo_hdr *) ((char *) packet + chklen);
    phdr->src = iplocal->ip_src.s_addr;
    phdr->dst = iplocal->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_TCP;
    phdr->len = ntohs((tcplocal->th_off * 4) + pac->datalen);
    /* tcp checksum */
    tcplocal->th_sum = checksum_comp((unsigned short *) tcplocal,
                                     chklen - sizeof(*iplocal) + sizeof(*phdr));

    return packet;
}

/**
 * 组建udp/ip回包
 */
char* build_udpip_packet(const struct ip_packet* pac, unsigned int *packetlen) {
    char *packet;
    struct ip *iplocal;
    struct udphdr *udplocal;
    pseudo_hdr *phdr;
    char *udpdata;
    /* fake length to account for 16bit word padding chksum */
    unsigned int chklen;
    uint16_t ipid = 0;
    uint8_t ttl = 64;

    *packetlen = sizeof(*iplocal) + sizeof(*udplocal) + pac->datalen;
    LOGD(DVPN, "packetlen %d, datalen %d.", *packetlen, pac->datalen);
    if (*packetlen % 2)
        chklen = *packetlen + 1;
    else
        chklen = *packetlen;

    packet = (char *) malloc(chklen + sizeof(*phdr));

    iplocal = (struct ip *) packet;
    udplocal = (struct udphdr *) ((char *) iplocal + sizeof(*iplocal));
    udpdata = (char *) (packet + sizeof(*iplocal) + sizeof(*udplocal));

    memset(packet, 0, chklen);

    iplocal->ip_v = 4;
    iplocal->ip_hl = 5;
    iplocal->ip_tos = 0;
    iplocal->ip_len = htons(*packetlen); /* must be in host byte order for FreeBSD */
    iplocal->ip_id = htons(ipid); /* kernel will fill with random value if 0 */
    iplocal->ip_off = 0;
    iplocal->ip_ttl = ttl;
    iplocal->ip_p = IPPROTO_UDP;
    iplocal->ip_src.s_addr = pac->ip->ip_src.s_addr;
    iplocal->ip_dst.s_addr = pac->ip->ip_dst.s_addr;
    iplocal->ip_sum = 0;
    iplocal->ip_sum = checksum_comp((unsigned short *) iplocal, sizeof(struct ip));

    udplocal->uh_sport = pac->udp->uh_sport;
    udplocal->uh_dport = pac->udp->uh_dport;
    udplocal->uh_ulen = htons(sizeof(*udplocal) + pac->datalen);
    udplocal->uh_sum = 0;

    memcpy(udpdata, pac->data, pac->datalen); // copy tcp data to packet

    /* pseudo header used for checksumming */
    phdr = (struct pseudo_hdr *) ((char *) packet + chklen);
    phdr->src = iplocal->ip_src.s_addr;
    phdr->dst = iplocal->ip_dst.s_addr;
    phdr->mbz = 0;
    phdr->proto = IPPROTO_UDP;
    phdr->len = htons(sizeof(*udplocal) + pac->datalen);
    /* tcp checksum */
    udplocal->uh_sum = checksum_comp((unsigned short *) udplocal,
                                     chklen - sizeof(*iplocal) + sizeof(*phdr));

    return packet;
}

