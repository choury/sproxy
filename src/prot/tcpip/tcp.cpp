#include "common/common.h"
#include "tcp.h"
#include "misc/net.h"

#include <stdlib.h>

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

static void SendAck(std::weak_ptr<TcpStatus> status);
static void CloseProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
static void DefaultProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len);
#define GetWeak(ptr) std::weak_ptr<std::remove_reference<decltype(*(ptr))>::type>(ptr)

ssize_t Cap(std::shared_ptr<TcpStatus> status) {
    if(status->state != TCP_ESTABLISHED && status->state != TCP_CLOSE_WAIT){
        return 0;
    }
    assert(nobefore(status->sent_seq, status->recv_ack));
    return (ssize_t)(status->window << status->recv_wscale) 
                    - (ssize_t)(status->sent_seq - status->recv_ack);
}

void consumeData(std::shared_ptr<TcpStatus> status) {
    if(status->rbuf.length() > 0 || (status->flags & TCP_FIN_RECVD)){
        SendAck(status);
    }
}

static size_t bufleft(std::shared_ptr<TcpStatus> status) {
    return status->rbuf.cap();
}

void Resent(std::weak_ptr<TcpStatus> status_) {
    if(status_.expired()){
        return;
    }
    auto status = status_.lock();
    assert(!status->sent_list.empty());
    if(status->dupack >= 3) {
        LOG("%s getdupack: %d, resent packet\n", storage_ntoa(&status->src), status->dupack);
        status->dupack = 0;
    }else {
        LOG("%s rto timeout: %d, resent packet\n", storage_ntoa(&status->src), status->rto);
        status->rto = std::min(status->rto * 2, (uint32_t) 1000);
    }
    if(status->sack == nullptr) {
        auto it = status->sent_list.begin();
        it->pac->tcp
                ->setack(status->want_seq)
                ->setwindow(bufleft(status) >> status->send_wscale);
        it->pac->build_packet(it->bb);
        status->sendCB(it->pac, it->bb.data(), it->bb.len);
        it->bb.reserve(it->pac->gethdrlen());
    }else {
        for(auto& it : status->sent_list){
            auto seq = it.pac->tcp->getseq();
            if(before(seq, status->sack->left)) {
                it.pac->tcp
                        ->setack(status->want_seq)
                        ->setwindow(bufleft(status) >> status->send_wscale);
                it.pac->build_packet(it.bb);
                status->sendCB(it.pac, it.bb.data(), it.bb.len);
                it.bb.reserve(it.pac->gethdrlen());
            }else {
                break;
            }
        }
        sack_release(&status->sack);
    }
    status->rto_job = status->jobHandler.updatejob(status->rto_job,
                                                   std::bind(&Resent, status_),
                                                   status->rto);
}

void PendPkg(std::shared_ptr<TcpStatus> status, std::shared_ptr<Ip> pac, Buffer&& bb) {
    pac->build_packet(bb);
    status->sendCB(pac, bb.data(), bb.len);
    bb.reserve(pac->gethdrlen());
    uint8_t flags = pac->tcp->getflag();
    if((flags & TH_RST) || (flags == TH_ACK && bb.len == 0)) {
        return;
    }
    if(status->sent_list.empty()) {
        status->rto_job = status->jobHandler.updatejob(status->rto_job,
                                                       std::bind(&Resent, GetWeak(status)),
                                                       status->rto);
    }
    status->sent_list.emplace_back(tcp_sent{pac, getmtime(), std::move(bb)});
}

// LISTEN or SYN-RECEIVED
void SynProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, const char*, size_t) {
    assert(status->state == TCP_LISTEN || status->state == TCP_SYN_RECV);
    uint32_t seq = pac->tcp->getseq();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST) {
        status->state = TCP_CLOSE;
        status->errCB(pac, TCP_RESET_ERR);
        return;
    }
    if((flag & TH_SYN) == 0 || (flag & TH_ACK) != 0) {
        LOGD(DVPN, "reply rst packets except syn\n");
        status->sent_seq = pac->tcp->getack();
        status->want_seq = seq + 1;
        SendRst(status);
        status->errCB(pac, TCP_RESET_ERR);
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
    // 因为syn包中的wscale不生效，所以这里做下修正，为了bufleft不用特殊处理这种情况
    status->window >>= status->recv_wscale;
    status->reqCB(pac);
}

// SYN-RECEIVED --> ESTANBLISHED
void SendSyn(std::shared_ptr<TcpStatus> status) {
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
    status->PkgProc = std::bind(&DefaultProc, status, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);

    PendPkg(status, pac, nullptr);
}

void UnReach(std::shared_ptr<TcpStatus> status, uint8_t code) {
    assert(status->state == TCP_SYN_RECV);
    Unreach(std::dynamic_pointer_cast<IpStatus>(status), code);
    status->state = TCP_CLOSE;
}

// ESTABLISHED or CLOSE-WAIT or FIN-WAIT1 or FIN-WAIT2
// 只有这个函数会从对端接收数据(data)
void DefaultProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    assert(status->state == TCP_ESTABLISHED ||
           status->state == TCP_CLOSE_WAIT ||
           status->state == TCP_FIN_WAIT1 ||
           status->state == TCP_FIN_WAIT2);
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST){//rst包，不用回包，直接断开
        status->state = TCP_CLOSE;
        status->errCB(pac, TCP_RESET_ERR);
        return;
    }

    if(seq != status->want_seq){
        if(seq == status->want_seq - 1) {
            LOGD(DVPN, "%s get keep-alive pkt, reply ack(%u/%u).\n", storage_ntoa(&status->src), seq, status->want_seq);
        } else {
            LOG("%s get unwanted pkt, reply ack(%u/%u).\n", storage_ntoa(&status->src), seq, status->want_seq);
        }
        status->sent_ack = status->want_seq - 1; //to force send tcp ack
        status->ack_job = status->jobHandler.updatejob(status->ack_job,
                                                       std::bind(&SendAck, GetWeak(status)), 0);
        return;
    }

    if(flag & TH_ACK){
        if(after(ack, status->sent_seq)) {
            LOG("%s get ack from unsent seq (%u/%u), rst it\n", storage_ntoa(&status->src), ack, status->sent_seq);
            SendRst(status);
            status->errCB(pac, TCP_RESET_ERR);
            return;
        }

        if(status->sent_list.empty() || before(ack, status->recv_ack)) {
            goto left;
        }
        if(ack == status->recv_ack) {
            status->dupack ++;
            if(status->dupack >= 3) {
                status->rto_job = status->jobHandler.updatejob(status->rto_job,
                                                               std::bind(&Resent, GetWeak(status)), 0);
                if(status->options & (1 << TCPOPT_SACK_PERMITTED)) {
                    pac->tcp->getsack(&status->sack);
                }
            }
            goto left;
        }
        status->dupack = 0;
        sack_release(&status->sack);
        status->recv_ack = ack;
        status->ackCB(pac);
        if(status->state == TCP_FIN_WAIT1 && ack == status->sent_seq){
            status->state = TCP_FIN_WAIT2;
        }
        uint32_t rtt = UINT32_MAX;
        uint32_t now = getmtime();
        while(!status->sent_list.empty()){
            auto& front = status->sent_list.front();
            uint32_t start_seq = front.pac->tcp->getseq();
            uint32_t end_seq = start_seq + front.bb.len;
            uint8_t flags = front.pac->tcp->getflag();
            if(flags & (TH_SYN | TH_FIN)){
                end_seq ++;
            }
            if(before(start_seq,  ack)) {
                if(now - front.when < rtt) {
                    rtt = now - front.when;
                }
            }
            if(noafter(end_seq, ack)) {
                status->sent_list.pop_front();
            }else{
                break;
            }
        }
        assert(rtt != UINT32_MAX);
        if(status->srtt == 0) {
            status->srtt = rtt;
            status->rttval = rtt/2;
        }else {
            status->rttval = (3 * status->rttval + labs((long) status->srtt - (long)rtt)) / 4;
            status->srtt = (7 * status->srtt + rtt) / 8;
        }
        status->rto = std::max(status->srtt + 4 * status->rttval, (uint32_t)100);
        LOGD(DVPN, "tcp rtt: %d, srtt: %d, rttval: %d, rto: %d\n", rtt, status->srtt, status->rttval, status->rto);
        if(status->sent_list.empty()) {
            status->jobHandler.deljob(&status->rto_job);
        }else{
            status->rto_job = status->jobHandler.updatejob(status->rto_job,
                                                           std::bind(&Resent, GetWeak(status)),
                                                           status->rto);
        }
    }
left:
    status->window = pac->tcp->getwindow();
    if(flag & TH_FIN){ //fin包，回ack包
        status->want_seq++;
        status->flags |= TCP_FIN_RECVD;
        switch(status->state){
        case TCP_CLOSE_WAIT:
            LOG("%s get dup fin, send rst back\n", storage_ntoa(&status->src));
            SendRst(status);
            status->errCB(pac, TCP_RESET_ERR);
            return;
        case TCP_ESTABLISHED:
            status->state = TCP_CLOSE_WAIT;
            break;
        case TCP_FIN_WAIT1:
            status->state = TCP_CLOSING;
            status->PkgProc = std::bind(&CloseProc, status, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
            break;
        case TCP_FIN_WAIT2:
            status->state = TCP_TIME_WAIT;
            status->PkgProc = std::bind(&CloseProc, status, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
            break;
        }
        status->ack_job = status->jobHandler.updatejob(status->ack_job,
                                                       std::bind(&SendAck, GetWeak(status)), 0);
        return;
    }

    size_t datalen = len - pac->gethdrlen();
    if(datalen > status->rbuf.cap()) {
        LOG("%s get pkt oversize of window (%zu/%zu), rst it\n",
            storage_ntoa(&status->src), datalen,  status->rbuf.cap());
        SendRst(status);
        status->errCB(pac, TCP_RESET_ERR);
        return;
    }
    if(datalen > 0) {
        //处理数据
        const char *data = packet + pac->gethdrlen();
        status->rbuf.put(data, datalen);
        status->want_seq += datalen;
        status->ack_job = status->jobHandler.updatejob(status->ack_job,
                                                       std::bind(&SendAck, GetWeak(status)), 0);
    }
}

void SendAck(std::weak_ptr<TcpStatus> status_) {
    if(status_.expired()){
        return;
    }
    auto status = status_.lock();
    assert(noafter(status->sent_ack, status->want_seq));
    if(status->flags & TCP_FIN_DELIVERED) {
        assert(status->rbuf.length() == 0);
    }else{
        auto pac = MakeIp(IPPROTO_TCP, &status->src, &status->dst);
        if(status->rbuf.length() > 0) {
            auto bb = status->rbuf.get();
            size_t len = status->dataCB(pac, bb.data(), bb.len);
            status->rbuf.consume(len);
        }
        if((status->flags & TCP_FIN_RECVD) && status->rbuf.length() == 0){
            status->dataCB(pac, nullptr, 0);
            status->flags |= TCP_FIN_DELIVERED;
        }
    }
    if(status->state == TCP_CLOSE) {
        status->jobHandler.deljob(&status->ack_job);
        return;
    }
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
    PendPkg(status, pac, nullptr);
    if(status->state == TCP_TIME_WAIT){
        status->state = TCP_CLOSE;
        status->errCB(MakeIp(IPPROTO_TCP, &status->src, &status->dst), NOERROR);
    }
}

void SendData(std::shared_ptr<TcpStatus> status, Buffer&& bb) {
    assert(status->state == TCP_ESTABLISHED || status->state == TCP_CLOSE_WAIT);
    if (bb.len == 0) {
        auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
        pac->tcp
            ->setseq(status->sent_seq++)
            ->setack(status->want_seq)
            ->setwindow(bufleft(status) >> status->send_wscale)
            ->setflag(TH_FIN | TH_ACK);

        //LOGD(DVPN, "%s (%u - %u)\n", key.getString("<-"), sent_seq-1, want_seq);
        status->sent_ack = status->want_seq;
        PendPkg(status, pac, nullptr);
        switch (status->state) {
        case TCP_ESTABLISHED:
            status->state = TCP_FIN_WAIT1;
            break;
        case TCP_CLOSE_WAIT:
            status->state = TCP_LAST_ACK;
            status->PkgProc = std::bind(&CloseProc, status, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
            break;
        }
        return;
    }
    size_t sendlen = bb.len;
    if((int)sendlen > Cap(status)){
        LOGE("%s send pkt will oversize of window (%zu/%d)\n",
             storage_ntoa(&status->src), sendlen,  (int)Cap(status));
    }
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
        ->setflag(TH_ACK);

    status->sent_seq += sendlen;
    status->sent_ack = status->want_seq;
    if (bb.len > sendlen) {
        Buffer cbb{bb.data(), sendlen, bb.id};
        PendPkg(status, pac, std::move(cbb));
        bb.reserve(sendlen);
        SendData(status, std::move(bb));
    }else{
        pac->tcp->setflag(TH_ACK | TH_PUSH);
        PendPkg(status, pac, std::move(bb));
    }
}

void SendRst(std::shared_ptr<TcpStatus> status) {
    status->state = TCP_CLOSE;
    auto pac = MakeIp(IPPROTO_TCP, &status->dst, &status->src);
    pac->tcp
        ->setseq(status->sent_seq)
        ->setack(status->want_seq)
        ->setwindow(0)
        ->setflag(TH_RST | TH_ACK);

    PendPkg(status, pac, nullptr);
}

// LAST_ACK or CLOSING
void CloseProc(std::shared_ptr<TcpStatus> status, std::shared_ptr<const Ip> pac, const char*, size_t) {
    assert(status->state == TCP_LAST_ACK || status->state == TCP_CLOSING || status->state == TCP_TIME_WAIT);
    uint32_t ack = pac->tcp->getack();
    uint32_t seq = pac->tcp->getseq();
    uint8_t flag = pac->tcp->getflag();

    if(flag & TH_RST) {
        status->state = TCP_CLOSE;
        status->errCB(pac, TCP_RESET_ERR);
        return;
    }
    if(seq != status->want_seq){
        status->sent_ack = status->want_seq - 1; //to force send tcp ack
        status->ack_job = status->jobHandler.updatejob(status->ack_job,
                                                       std::bind(&SendAck, GetWeak(status)), 0);
        return;
    }

    if(flag & TH_ACK){
        if(ack == status->sent_seq) {
            status->sent_list.clear();
            status->state = TCP_CLOSE;
            status->errCB(pac, NOERROR);
            return;
        }
    } else {
        SendRst(status);
        status->errCB(pac, NOERROR);
        return;
    }
}
