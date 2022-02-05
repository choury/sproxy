#include "common/common.h"
#include "pcap.h"
#include "util.h"

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#if __APPLE__
#include <net/ethernet.h>
#else
#include <linux/if_ether.h>
#endif

int pcap_create(const char *file){
    int fd = open(file, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if(fd < 0){
        LOGE("failed to create pcap file: %s\n", strerror(errno));
        return -1;
    }
    pcap_hdr_t header = {
            .magic_number = htonl(PCAP_MAGIC),
            .version_major = htons(PCAP_MAJOR),
            .version_minor = htons(PCAP_MINOR),
            .sigfigs = 0,
            .thiszone = 0,
            .snaplen = htonl(0xffff),
            .network = htonl(1),
    };
    if(write(fd, &header, sizeof(header)) <= 0){
        LOGE("failed to write pcap header: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int pcap_write_with_generated_ethhdr(int fd, const void *data, size_t len){
    if(fd < 0) {
        return -1;
    }

    const struct ip* iphdr = (const struct ip*)data;
#if __APPLE__
    struct ether_header ethhdr;
    memcpy(ethhdr.ether_shost, "\x82\xf4\xff\x85\xc4\x00", sizeof(ethhdr.ether_shost));
    memcpy(ethhdr.ether_dhost, "\x82\xf4\xff\x85\xc4\x01", sizeof(ethhdr.ether_dhost));
#else
    struct ethhdr ethhdr;
    memcpy(ethhdr.h_source, "\x82\xf4\xff\x85\xc4\x00", sizeof(ethhdr.h_source));
    memcpy(ethhdr.h_dest, "\x82\xf4\xff\x85\xc4\x01", sizeof(ethhdr.h_dest));
#endif
    if(iphdr->ip_v == IPVERSION){
#if __APPLE__
        ethhdr.ether_type = htons(ETHERTYPE_IP);
#else
        ethhdr.h_proto = htons(ETH_P_IP);
#endif
    }else if(iphdr->ip_v == 6){
#if __APPLE__
        ethhdr.ether_type = htons(ETHERTYPE_IPV6);
#else
        ethhdr.h_proto = htons(ETH_P_IPV6);
#endif
    }else{
        LOGE("unknown ip version: %d\n", iphdr->ip_v);
        return -1;
    }

    uint64_t utime = getutime();
    pcap_pkt_hdr_t phdr = {
            .ts_sec = htonl(utime/1000000),
            .ts_usec = htonl(utime%1000000),
            .orig_len = htonl(len + sizeof(ethhdr)),
            .incl_len = htonl(len + sizeof(ethhdr)),
    };
    if(write(fd, &phdr, sizeof(phdr)) < 0){
        LOGE("failed to write pcap packet header: %s\n", strerror(errno));
        return -1;
    }
    if(write(fd, &ethhdr, sizeof(ethhdr)) < 0){
        LOGE("failed to write ether header: %s\n", strerror(errno));
        return -1;
    }
    return write(fd, data, len);
}


void pcap_close(int fd){
    if(fd >= 0) {
        close(fd);
    }
}
