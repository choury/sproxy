#ifndef RUDP_H__
#define RUDP_H__

#include "base.h"
#include "misc/index.h"

#include <list>

class Rudp_server;
class TTL;

struct Rudp_head{
    uint32_t id;
    uint32_t seq;
    uint32_t time;
    uint16_t window;
#define RUDP_TYPE_DATA  0
#define RUDP_TYPE_ACK   1
    uint8_t  type;
    uint8_t  checksum;
}__attribute__((packed));

#define RUDP_LEN 1280
#define RUDP_MTU (RUDP_LEN+sizeof(Rudp_head))

struct Rudp_stats{
    uint32_t tick_recvpkg = 0;
    uint32_t tick_recvdata = 0;
#ifndef NDEBUG
    uint32_t recv_begin = 0;
    uint32_t recv_end = 0;
    uint32_t discard_begin = 0;
    uint32_t discard_end = 0;
#endif
};

class RudpRWer: public RWer {
    uint32_t id = 0;
    uint16_t port;
    char     hostname[DOMAINLIMIT] = {0};
    Rudp_server* ord = nullptr;
    sockaddr_un addr;
    unsigned char read_buff[BUF_LEN * 64];
    unsigned char write_buff[BUF_LEN * 64];
    std::list<std::pair<uint32_t, uint32_t>> read_seqs;
    TTL* recv_pkgs;
    uint32_t gaps[RUDP_LEN/sizeof(uint32_t)];
    uint32_t gap_num=0;

    uint32_t recv_ack = 0;
    uint32_t recv_time = 0;
    uint32_t send_pos = 0;
    uint32_t resend_pos = 0;
    uint32_t write_seq = 0;
    uint32_t bucket_limit = 10;
    uint32_t rtt_time = 50;
    uint32_t ackhold_times = 0;
    uint32_t ack_time;
    uint32_t data_time;
    uint32_t resend_time = 0;
    uint32_t tick_time;
#define RUDP_SEND_TIMEOUT    1
#define RUDP_RESET            2
    uint32_t flags = 0;

    void connected();
    void defaultHE(uint32_t events);

    int send();
    void ack();
    uint32_t send_pkg(uint32_t seq, uint32_t window, size_t len);
    ssize_t Write(const void* buff, size_t len) override;
    void handle_pkg(const Rudp_head* head, size_t size, Rudp_stats* stats);
    void finish_recv(Rudp_stats* stats);
public:
    RudpRWer(int fd, uint32_t id, Rudp_server* ord);
    RudpRWer(const char* host, uint16_t port);
    ~RudpRWer();

    int PushPkg(const Rudp_head* pkg, size_t len, const sockaddr_un* addr);

    virtual bool supportReconnect() override;
    virtual void Reconnect() override;
    //for read buffer
    virtual size_t rlength() override;
    virtual const char *data() override;
    virtual void consume(const char* data, size_t l) override;

    static void Dnscallback(RudpRWer* rwer, const char*, std::list<sockaddr_un> addrs);
    static int rudp_send(RudpRWer* r);
    static int rudp_ack(RudpRWer* r);
};


bool operator<(const sockaddr_un a, const sockaddr_un b);

class Rudp_server: public Ep {
    uint16_t port;
    unsigned char buff[RUDP_MTU];
    uint32_t Maxid = 0;
    Index2<int, sockaddr_un, RudpRWer*> connections;
    virtual void defaultHE(uint32_t events);
public:
    explicit Rudp_server(int fd, uint16_t port): Ep(fd), port(port){
        setEpoll(EPOLLIN);
        handleEvent = (void (Ep::*)(uint32_t))&Rudp_server::defaultHE;
    }
    void evict(int id);
    virtual void dump_stat(){
        LOG("Rudp_server %p\n", this);
    }
};

#endif
