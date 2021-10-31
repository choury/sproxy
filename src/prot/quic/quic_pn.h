//
// Created by 周威 on 2021/8/22.
//

#ifndef SPROXY_QUIC_PN_H
#define SPROXY_QUIC_PN_H

#include "quic_pack.h"

#include <stdint.h>
#include <list>
#include <map>
#include <functional>


class Chop{
    void refactor();
public:
    std::list<std::pair<uint64_t, uint64_t>> items;
    uint64_t latest_time = 0;

    Chop(){};
    Chop(const quic_ack* frame);
    void PushPn(uint64_t pn);
    bool Has(uint64_t pn);
    // delete number before pN;
    void Erase(uint64_t pn);
    void dump();
};

class Rtt{
public:
    uint64_t latest_rtt    = 0;
    uint64_t min_rtt       = UINT64_MAX;
    uint64_t smoothed_rtt  = 333000;
    uint64_t rttvar        = 166500;
};

/*
Ack-eliciting frames:
All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting.

Ack-eliciting packets:
Packets that contain ack-eliciting frames elicit an ACK from the receiver within the
maximum acknowledgment delay and are called ack-eliciting packets.

In-flight packets:
Packets are considered in flight when they are ack-eliciting or contain a PADDING frame,
and they have been sent but are not acknowledged, declared lost, or discarded along with old keys.
 */

struct quic_packet_pn{
    uint64_t pn;
    bool ack_eliciting;
    bool in_flight;
    size_t sent_bytes;
    uint64_t time_sent;
    std::list<quic_frame*> frames;
};


class pn_namespace{
    void PnAcknowledged(quic_packet_pn& pn);
public:
    Chop     pns;
    bool     should_ack  = false;
    uint64_t current     = 0;
    uint64_t largest_acked_packet = 0;
    uint64_t latest_ack  = 0;
    uint64_t ack_delay_exponent = 3;
    uint64_t time_of_last_ack_eliciting_packet = 0;
    uint64_t loss_time = UINT64_MAX;
    char     name;
    std::list <quic_frame*>    pend_frames;
    std::list <quic_packet_pn> sent_packets;
    std::list <quic_frame*>    lost_frames;
    uint64_t PendAck();
    bool HandleAck(const quic_ack* frame, Rtt* rtt, uint64_t max_delay_us, std::function<void(quic_frame*)> resendFrame);
    void DetectLostPackets(Rtt* rtt, std::function<void(quic_frame*)> resendFrame);
    void clear();
    ~pn_namespace();
};

#endif //SPROXY_QUIC_PN_H
