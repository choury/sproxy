#include "common/common.h"
#include "pcap.h"
#include "config.h"

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
            .magic_number = PCAP_MAGIC,
            .version_major = PCAP_MAJOR,
            .version_minor = PCAP_MINOR,
            .sigfigs = 0,
            .thiszone = 0,
            .snaplen = 0xffff,
            .network = 101,
    };
    if(write(fd, &header, sizeof(header)) <= 0){
        LOGE("failed to write pcap header: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

int pcap_write(int fd, const void *data, size_t len){
    if(fd < 0) {
        return -1;
    }

    size_t write_len = MIN(len, opt.pcap_len);
    uint64_t utime = getutime();
    pcap_pkt_hdr_t phdr = {
            .ts_sec = utime/1000000,
            .ts_usec = utime%1000000,
            .orig_len = len,
            .incl_len = write_len,
    };
    if(write(fd, &phdr, sizeof(phdr)) < 0){
        LOGE("failed to write pcap packet header: %s\n", strerror(errno));
        return -1;
    }
    return write(fd, data, write_len);
}


void pcap_close(int fd){
    if(fd >= 0) {
        close(fd);
    }
}
