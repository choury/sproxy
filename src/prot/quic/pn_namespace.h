//
// Created by choury on 24-6-6.
//

#ifndef SPROXY_PN_NAMESPACE_H
#define SPROXY_PN_NAMESPACE_H
#include "quic_pack.h"

#include <functional>

const uint64_t kPacketThreshold = 3;

struct Rtt{
    uint64_t first_rtt_sample = 0;
    uint64_t latest_rtt       = 0;
    uint64_t min_rtt          = UINT64_MAX;
    uint64_t smoothed_rtt     = 333000;
    uint64_t rttvar           = 166500;
};


class Chop{
    void refactor();
public:
    std::list<std::pair<uint64_t, uint64_t>> items;
    uint64_t latest_time = 0;

    Chop() = default;
    explicit Chop(const quic_ack* frame);
    void Add(uint64_t pn);
    bool Has(uint64_t pn);
    uint64_t Max();
    // delete number before pN;
    void EraseBefore(uint64_t pn);
    void dump();
};

class pn_namespace{
    typedef std::function<std::list<quic_packet_pn>(uint64_t pn, uint64_t ack,
                                                    std::list<quic_frame*>& pend_frames, size_t window)> send_func;
public:
    pn_namespace(char name, send_func sent);
    ~pn_namespace();
    send_func sent;
    uint64_t current_pn     = 0;
    bool     hasKey = false;
    char     name;
    Chop     tracked_receipt_pns;
    bool     should_ack  = false;
    uint64_t largest_acked_packet = UINT64_MAX;   // largest acked packet from peer
    uint64_t ack_delay_exponent = 3;
    uint64_t time_of_last_ack_eliciting_packet = 0;
    uint64_t ecn_ce_counters = 0;
    uint64_t loss_time = UINT64_MAX;
    std::list <quic_frame*>    pend_frames;
    std::list <quic_packet_pn> sent_packets;

    size_t sendPacket(size_t window, size_t delivered_bytes, uint64_t delivered_time);
    void PendAck();
    std::list<quic_packet_meta> DetectAndRemoveAckedPackets(const quic_ack* ack, Rtt* rtt,
                                                            uint64_t& ack_delay_us, uint64_t max_delay_us);
    std::list<quic_packet_pn> DetectAndRemoveLostPackets(Rtt* rtt);
    void clear();
};


#endif //SPROXY_PN_NAMESPACE_H
