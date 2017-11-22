#ifndef RUDP_H__
#define RUDP_H__

#include "common.h"
#include "misc/index.h"

#include <list>

class Rudp;
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
#define RUDP_BUF_LEN (1024*1024ull)

class Rudp_c{
    int fd = 0;
    uint32_t id = 0;
    Rudp* ord = nullptr;
    sockaddr_un addr;
    unsigned char *read_buff;
    unsigned char *write_buff;
    std::list<std::pair<uint32_t, uint32_t>> read_seqs;
    TTL* recv_pkgs;
    uint32_t gaps[RUDP_LEN/sizeof(uint32_t)];
    uint32_t gap_num=0;

    uint32_t recv_ack = 0;
    uint32_t send_pos = 0;
    uint32_t resend_pos = 0;
    uint32_t write_seq = 0;
    uint32_t bucket_limit = 10;
    uint32_t rtt_time = 50;
    uint32_t ackhold_times = 0;
    uint32_t ack_time;
    uint32_t resend_time = 0;
    uint32_t tick_time;
#define RUDP_SEND_TIMEOUT    1
    uint32_t flags = 0;
    uint32_t send_pkg(uint32_t seq, uint32_t window, size_t len);
    void send_ack(uint32_t time, uint32_t window);
public:
    Rudp_c(int fd, uint32_t id, Rudp* ord);
    Rudp_c(const sockaddr_un* addr);
    ~Rudp_c();
    int Send();
    int Recv();

    int PushPkg(const Rudp_head* pkg, size_t len, const sockaddr_un* addr);
    ssize_t Write(const void* buff, size_t len);
    ssize_t Read(void* buff, size_t len);
    int GetFd();
    const sockaddr_un* GetPeer();
    static int rudp_send(Rudp_c* r);
};


bool operator<(const sockaddr_un a, const sockaddr_un b);

typedef void (*rudp_accept_cb)(void* param, Rudp_c*);
class Rudp {
    int fd;
    uint16_t port;
    rudp_accept_cb Accept = nullptr;
    void* AcceptParam = nullptr;
    uint32_t Maxid = 0;

    Index2<int, sockaddr_un, Rudp_c*> connections;
public:
    explicit Rudp(int fd, uint16_t port, rudp_accept_cb cb, void* param);
    void evict(int id);
    ~Rudp();
    int Recv();
};

#endif
