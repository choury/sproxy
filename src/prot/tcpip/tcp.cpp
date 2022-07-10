#include "common/common.h"
#include "tcp.h"
#include "misc/net.h"

/*


                              +---------+ ---------\      active OPEN
                              |  CLOSED |            \    -----------
                              +---------+<---------\   \   create TCB
                                |     ^              \   \  snd SYN
                   passive OPEN |     |   CLOSE        \   \
                   ------------ |     | ----------       \   \
                    create TCB  |     | delete TCB         \   \
                                V     |                      \   \
                              +---------+            CLOSE    |    \
                              |  LISTEN |          ---------- |     |
                              +---------+          delete TCB |     |
                   rcv SYN      |     |     SEND              |     |
                  -----------   |     |    -------            |     V
 +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
 |         |<-----------------           ------------------>|         |
 |   SYN   |                    rcv SYN                     |   SYN   |
 |   RCVD  |<-----------------------------------------------|   SENT  |
 |         |                    snd ACK                     |         |
 |         |------------------           -------------------|         |
 +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
   |           --------------   |     |   -----------
   |                  x         |     |     snd ACK
   |                            V     V
   |  CLOSE                   +---------+
   | -------                  |  ESTAB  |
   | snd FIN                  +---------+
   |                   CLOSE    |     |    rcv FIN
   V                  -------   |     |    -------
 +---------+          snd FIN  /       \   snd ACK          +---------+
 |  FIN    |<-----------------           ------------------>|  CLOSE  |
 | WAIT-1  |------------------                              |   WAIT  |
 +---------+          rcv FIN  \                            +---------+
   | rcv ACK of FIN   -------   |                            CLOSE  |
   | --------------   snd ACK   |                           ------- |
   V        x                   V                           snd FIN V
 +---------+                  +---------+                   +---------+
 |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
 +---------+                  +---------+                   +---------+
   |                rcv ACK of FIN |                 rcv ACK of FIN |
   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
   |  -------              x       V    ------------        x       V
    \ snd ACK                 +---------+delete TCB         +---------+
     ------------------------>|TIME WAIT|------------------>| CLOSED  |
                              +---------+                   +---------+

 */

#define TCP_WSCALE   9u

ssize_t TcpHE::Cap(std::shared_ptr<IpStatus> status_) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    if(status->state != TCP_ESTABLISHED && status->state != TCP_CLOSE_WAIT){
        return 0;
    }
    assert(nobefore(status->sent_seq, status->recv_ack));
    return (ssize_t)(status->window << status->recv_wscale) 
                    - (ssize_t)(status->sent_seq - status->recv_ack);
}

size_t TcpHE::bufleft(std::shared_ptr<TcpStatus> status) {
    return BUF_LEN;
}

// LISTEN or SYN-RECEIVED
void TcpHE::SynProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char*, size_t) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    assert(status->state == TCP_LISTEN || status->state == TCP_SYN_RECV);
    uint32_t seq = pac->tcp->getseq();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST) {
        status->state = TCP_CLOSE;
        ErrProc(pac, TCP_RESET_ERR);
        return;
    }
    if((flag & TH_SYN) == 0 || (flag & TH_ACK) != 0) {
        LOGD(DVPN, "reply rst packets except syn\n");
        status->sent_seq = pac->tcp->getack();
        SendRst(status);
        ErrProc(pac, TCP_RESET_ERR);
        return;
    }
    if(status->state == TCP_SYN_RECV) {
        LOGD(DVPN, "drop dup syn packet\n");
        return;
    }
    status->state = TCP_SYN_RECV;
    status->src = pac->getsrc();
    status->dst = pac->getdst();
    status->sent_seq = getmtime();
    status->sent_ack = 0;
    status->recv_ack = status->sent_seq;
    status->want_seq = seq + 1;
    status->window = pac->tcp->getwindow();
    status->options = pac->tcp->getoptions();
    status->mss = pac->tcp->getmss();
    if(status->options & (1u<<TCPOPT_WINDOW)){
        status->recv_wscale = pac->tcp->getwindowscale();
        status->send_wscale = TCP_WSCALE;
    }else{
        status->recv_wscale = 0;
        status->send_wscale = 0;
    }
    ReqProc(pac);
}

// SYN-RECEIVED --> ESTANBLISHED
void TcpHE::SendSyn(std::shared_ptr<TcpStatus> status) {
    assert(status->state == TCP_SYN_RECV);
    // tcp 创建回包 (syn + ack)
    auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
    // rfc7323: The window field in a segment where the SYN bit is set (i.e., a <SYN>
    // or <SYN,ACK>) MUST NOT be scaled
    pac->tcp
        ->setseq(status->sent_seq++)
        ->setack(status->want_seq)
        ->setwindowscale(status->send_wscale)
        ->setwindow(bufleft(status))
        ->setmss(Min(status->mss, BUF_LEN))
        ->setflag(TH_ACK | TH_SYN);

    if (status->options & (1 << TCPOPT_SACK_PERMITTED)) {
        pac->tcp->setsack(nullptr);
    }

    status->sent_ack = status->want_seq;
    status->state = TCP_ESTABLISHED;
    status->InProc = reinterpret_cast<InProc_t>(&TcpHE::DefaultProc);
    sendPkg(pac, nullptr);
}

void TcpHE::Unreach(std::shared_ptr<IpStatus> status_, uint8_t code) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    assert(status->state == TCP_SYN_RECV);
    IpBase::Unreach(status_, code);
    status->state = TCP_CLOSE;
}

// ESTABLISHED or CLOSE-WAIT or FIN-WAIT1 or FIN-WAIT2
// 只有这个函数会从对端接收数据(data)
void TcpHE::DefaultProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    assert(status->state == TCP_ESTABLISHED ||
           status->state == TCP_CLOSE_WAIT ||
           status->state == TCP_FIN_WAIT1 ||
           status->state == TCP_FIN_WAIT2);
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST){//rst包，不用回包，直接断开
        status->state = TCP_CLOSE;
        ErrProc(pac, TCP_RESET_ERR);
        return;
    }
    if((flag & TH_ACK) && ack > status->sent_seq) {
        LOGD(DVPN, "get ack from unsent seq, rst it\n");
        SendRst(status);
        ErrProc(pac, TCP_RESET_ERR);
        return;
    }

    if(seq != status->want_seq){
        LOGD(DVPN, "get keepalive pkt or unwanted pkt, reply ack(%u).\n", status->want_seq);
        status->sent_ack = status->want_seq - 1; //to force send tcp ack
        SendAck(status);
        return;
    }

    if((flag & TH_ACK) && after(ack, status->recv_ack)){
        status->recv_ack = ack;
        TcpAckProc(pac);
        if(status->state == TCP_FIN_WAIT1 && status->recv_ack == status->sent_seq){
            status->state = TCP_FIN_WAIT2;
        }
    }

    if(flag & TH_FIN){ //fin包，回ack包
        status->want_seq++;
        switch(status->state){
        case TCP_CLOSE_WAIT:
            LOGD(DVPN, "get dup fin, send rst back\n");
            SendRst(status);
            ErrProc(pac, TCP_RESET_ERR);
            return;
        case TCP_ESTABLISHED:
            status->state = TCP_CLOSE_WAIT;
            break;
        case TCP_FIN_WAIT1:
            status->state = TCP_CLOSING;
            status->InProc = reinterpret_cast<InProc_t>(&TcpHE::CloseProc);
            break;
        case TCP_FIN_WAIT2:
            status->state = TCP_TIME_WAIT;
            status->InProc = reinterpret_cast<InProc_t>(&TcpHE::CloseProc);
            break;
        }
        SendAck(status);
        DataProc(pac, nullptr, 0);
        return;
    }

    size_t datalen = len - pac->gethdrlen();
    status->window = pac->tcp->getwindow();
    if(datalen > 0){
        //处理数据
        const char* data = packet + pac->gethdrlen();
        if(DataProc(pac, data, datalen)){
            status->want_seq += datalen;
        }
    }
    SendAck(status);
}

void TcpHE::SendAck(std::shared_ptr<TcpStatus> status) {
    assert(noafter(status->sent_ack, status->want_seq));
    if(status->sent_ack == status->want_seq){
        return;
    }
    int buflen = bufleft(status);
    if(buflen < 0) buflen = 0;
    //创建回包
    auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
    pac->tcp
        ->setseq(status->sent_seq)
        ->setack(status->want_seq)
        ->setwindow(buflen >> status->send_wscale)
        ->setflag(TH_ACK);

    status->sent_ack = status->want_seq;
    sendPkg(pac , nullptr);
}

void TcpHE::SendData(std::shared_ptr<IpStatus> status_, Buffer&& bb) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    assert(status->state == TCP_ESTABLISHED || status->state == TCP_CLOSE_WAIT);
    if (bb.len == 0) {
        LOGD(DVPN, "write fin packet\n");
        auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
        pac->tcp
            ->setseq(status->sent_seq++)
            ->setack(status->want_seq)
            ->setwindow(bufleft(status) >> status->send_wscale)
            ->setflag(TH_FIN | TH_ACK);

        //LOGD(DVPN, "%s (%u - %u)\n", key.getString("<-"), sent_seq-1, want_seq);
        status->sent_ack = status->want_seq;
        sendPkg(pac, std::move(bb));
        switch (status->state) {
            case TCP_ESTABLISHED:
                status->state = TCP_FIN_WAIT1;
                break;
            case TCP_CLOSE_WAIT:
                status->state = TCP_LAST_ACK;
                break;
        }
        status->InProc = reinterpret_cast<InProc_t>(&TcpHE::CloseProc);
        return;
    }
    assert((status->window << status->recv_wscale) - (status->sent_seq - status->recv_ack) >= bb.len);
    size_t sendlen = bb.len;
    if (sendlen > status->mss) {
        //LOGD(DVPN, "%s: mss smaller than send size (%zu/%u)!\n", key.getString("<-"), bb.len, mss);
        sendlen = status->mss;
    }
    //LOGD(DVPN, "%s (%u - %u) size: %zu\n", key.getString("<-"), sent_seq, want_seq, sendlen);
    auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
    pac->tcp
        ->setseq(status->sent_seq)
        ->setack(status->want_seq)
        ->setwindow(bufleft(status) >> status->send_wscale)
        ->setflag(TH_ACK | TH_PUSH);

    status->sent_seq += sendlen;
    status->sent_ack = status->want_seq;
    if (bb.len > sendlen) {
        Buffer cbb{bb.data(), sendlen, bb.id};
        sendPkg(pac, std::move(cbb));
        bb.reserve(sendlen);
        SendData(status, std::move(bb));
    }else{
        sendPkg(pac, std::move(bb));
    }
}

void TcpHE::SendRst(std::shared_ptr<TcpStatus> status) {
    status->state = TCP_CLOSE;
    auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
    pac->tcp
        ->setseq(status->sent_seq)
        ->setwindow(0)
        ->setflag(TH_RST);
    sendPkg(pac, nullptr);
}

// LAST_ACK or CLOSING or TIME_WAIT
void TcpHE::CloseProc(std::shared_ptr<IpStatus> status_, std::shared_ptr<const Ip> pac, const char*, size_t) {
    std::shared_ptr<TcpStatus> status = std::static_pointer_cast<TcpStatus>(status_);
    assert(status->state == TCP_TIME_WAIT || status->state == TCP_LAST_ACK || status->state == TCP_CLOSING);
    uint32_t ack = pac->tcp->getack();
    uint32_t seq = pac->tcp->getseq();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST) {
        status->state = TCP_CLOSE;
        ErrProc(pac, TCP_RESET_ERR);
        return;
    }
    if(seq != status->want_seq){
        status->sent_ack = status->want_seq - 1; //to force send tcp ack
        SendAck(status);
        return;
    }

    if(flag & TH_ACK){
        if(ack == status->sent_seq) {
            status->state = TCP_CLOSE;
            ErrProc(pac, NOERROR);
            return;
        }
    } else {
        SendRst(status);
        return;
    }
}


