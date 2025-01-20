#ifndef PCAP__H__
#define PCAP__H__
#include <stdint.h>

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_MAJOR 2
#define PCAP_MINOR 4

typedef struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type */
} __attribute__((packed)) pcap_hdr_t;

typedef struct pcap_pkt_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} __attribute__((packed)) pcap_pkt_hdr_t;


#ifdef  __cplusplus
extern "C" {
#endif

int pcap_create(const char *file);

int pcap_write(int fd, const void *data, size_t len);

void pcap_close(int fd);

#ifdef  __cplusplus
}
#endif

#endif
