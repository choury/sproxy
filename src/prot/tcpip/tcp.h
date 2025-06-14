#ifndef TCP_H__
#define TCP_H__

#include "ipbase.h"
#include "misc/buffer.h"
#include "misc/job.h"

#include <stddef.h>
#include <list>
#ifdef __APPLE__
#include <netinet/tcp_fsm.h>

#define TCP_CLOSE             TCPS_CLOSED
#define TCP_LISTEN            TCPS_LISTEN
#define TCP_SYN_SENT          TCPS_SYN_SENT
#define TCP_SYN_RECV          TCPS_SYN_RECEIVED
#define TCP_ESTABLISHED       TCPS_ESTABLISHED
#define TCP_CLOSE_WAIT        TCPS_CLOSE_WAIT
#define TCP_FIN_WAIT1         TCPS_FIN_WAIT_1
#define TCP_CLOSING           TCPS_CLOSING
#define TCP_LAST_ACK          TCPS_LAST_ACK
#define TCP_FIN_WAIT2         TCPS_FIN_WAIT_2
#define TCP_TIME_WAIT         TCPS_TIME_WAIT

#endif

struct TcpStatus;
void SynProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, Buffer&& bb);
void SendData(std::shared_ptr<TcpStatus> status, Buffer&& bb);
void UnReach(std::shared_ptr<TcpStatus> status, uint8_t code);

void SendSyn(std::shared_ptr<TcpStatus> status);
void SendRst(std::shared_ptr<TcpStatus> status);
ssize_t Cap(std::shared_ptr<TcpStatus> status);
void consumeData(std::shared_ptr<TcpStatus> status);

struct tcp_sent{
    std::shared_ptr<Ip> pac;
    uint32_t first_sent;
    uint32_t last_sent;
    Buffer   bb;
};

#define RTO_MAX         ((uint32_t)1000)  // 1s
#define RTO_FACTOR_MAX  ((uint32_t)30)

//Tcp 不需要aged_job，原因是本机的tcp（Host）连接总会被销毁的，
//即使是代理请求，末端的tcp连接也会销毁的，就会发送信号过来，
//销毁的时候如果vpn这边的tcp还没有销毁，那么就会发送RST报文，这个时候就会自动清理掉了
struct TcpStatus: public IpStatus{
//use for flags from IpStatus
#define TCP_FIN_RECVD     0x100
#define TCP_FIN_DELIVERED 0x200
#define TCP_KEEPALIVING   0x400
#define TCP_LOCALIP       0x800
#define TCP_ACK_ONLY      0x1000
    uint8_t    state  = TCP_LISTEN;
    uint8_t    recv_wscale;
    uint8_t    send_wscale;
    uint16_t   window;
    uint16_t   mss = TCP_MSS;
    uint32_t   sent_seq; //下一个发送的报文的序列号，意思是上一个发送的序列号是sent_seq-1
    uint32_t   sent_ack;
    uint32_t   recv_ack;
    uint32_t   want_seq; //收到的对方 seq+1，可以直接当作ack
    uint64_t   options = 0;
    uint32_t   srtt = 0;
    uint32_t   rttval = 0;
    uint32_t   rto = RTO_MAX;
    uint32_t   rto_factor = 1;
    uint32_t   dupack = 0;
    CBuffer    rbuf;
    std::list<tcp_sent> sent_list;
    Sack       *sack = nullptr;
    Job        ack_job = nullptr;
    Job        rto_job = nullptr;
    Job        pull_job = nullptr;
    Job        keepalive_job = nullptr;
};



#endif
