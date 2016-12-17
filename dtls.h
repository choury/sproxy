#ifndef DTLS_H__
#define DTLS_H__
#include "vssl.h"

#include <list>
#include <queue>
#include <stdint.h>
#include <stddef.h>

#define DTLS_LEN 1280
#define DTLS_MTU (DTLS_LEN+sizeof(Dtls_head))

class TTL{
    std::queue<std::pair<uint32_t, uint32_t>> data;
    uint32_t sum = 0;
public:
    void add(uint32_t value);
    uint32_t getsum();
};

class Dtls:public Ssl{
    unsigned char *read_buff;
    unsigned char *write_buff;
    std::list<std::pair<uint32_t, uint32_t>> read_seqs;
    TTL recv_pkgs;
    uint32_t gaps[DTLS_LEN/sizeof(uint32_t)];
    uint32_t gap_num=0;

    uint32_t recv_ack = 0;
    uint32_t send_pos = 0;
    uint32_t resend_pos = 0;
    uint32_t write_seq = 0;
    uint32_t bucket_limit = 10;
    uint32_t rtt_time = 50;
    uint32_t ackhold_times = 0;
    uint32_t ack_time;
    uint32_t tick_time;
    int recv();
    int send();
    uint32_t send_pkg(uint32_t seq, uint32_t window, size_t len);
    void send_ack(uint32_t time, uint32_t window);
public:
    Dtls(SSL *ssl);
    virtual ~Dtls();
    virtual ssize_t write(const void *buff, size_t size) override;
    virtual ssize_t read(void *buff, size_t size) override;
    static void dtls_send(Dtls* dtls);
};


#endif
