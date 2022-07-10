#ifndef TCP_H__
#define TCP_H__

#include "ipbase.h"
#include <stddef.h>
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
class TcpHE: virtual public IpBase {
protected:
    virtual void TcpAckProc(std::shared_ptr<const Ip> pac) = 0;
    size_t bufleft(std::shared_ptr<TcpStatus> status);
public:
    void SynProc(std::shared_ptr<IpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void DefaultProc(std::shared_ptr<IpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void CloseProc(std::shared_ptr<IpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
    void SendData(std::shared_ptr<IpStatus> status, Buffer&& bb);
    void Unreach(std::shared_ptr<IpStatus>, uint8_t code);

    void SendSyn(std::shared_ptr<TcpStatus> status);
    void SendRst(std::shared_ptr<TcpStatus> status);
    void SendAck(std::shared_ptr<TcpStatus> status);
    ssize_t Cap(std::shared_ptr<IpStatus> status);
};

//Tcp 不需要aged_job，原因是本机的tcp（Host）连接总会被销毁的，
//即使是代理请求，末端的tcp连接也会销毁的，就会发送信号过来，
//销毁的时候如果vpn这边的tcp还没有销毁，那么就会发送RST报文，这个时候就会自动清理掉了
struct TcpStatus: public IpStatus{
    uint8_t    state  = TCP_LISTEN;
    uint32_t   sent_seq; //下一个发送的报文的序列号，意思是上一个发送的序列号是sent_seq-1
    uint32_t   sent_ack;
    uint32_t   recv_ack;
    uint32_t   want_seq; //收到的对方 seq+1，可以直接当作ack
    uint16_t   window;
    uint16_t   mss;
    uint64_t   options;
    uint8_t    recv_wscale;
    uint8_t    send_wscale;
};



#endif
