//
// Created by 周威 on 2021/8/22.
//

#ifndef SPROXY_QUIC_QOS_H
#define SPROXY_QUIC_QOS_H

#include "quic_pack.h"
#include "misc/util.h"
#include "misc/job.h"

#include <openssl/ssl.h>
#include <stdint.h>
#include <list>
#include <map>
#include <functional>

const uint64_t max_datagram_size = 1372;
const uint64_t kInitialWindow = 14720;
const uint64_t kMinimumWindow = 2 * max_datagram_size;
const double  kPacketThreshold = 3;
const uint64_t kGranularity = 1000; // 1ms
const double  kLossReductionFactor = 0.5;
const double  kPersistentCongestionThreshold = 3;

#define QUIC_PACKET_NAMESPACE_INITIAL 0
#define QUIC_PACKET_NAMESPACE_HANDSHAKE 1
#define QUIC_PAKCET_NAMESPACE_APP 2


class Chop{
    void refactor();
public:
    std::list<std::pair<uint64_t, uint64_t>> items;
    uint64_t latest_time = 0;

    Chop(){};
    Chop(const quic_ack* frame);
    void Add(uint64_t pn);
    bool Has(uint64_t pn);
    // delete number before pN;
    void Erase(uint64_t pn);
    void dump();
};

class Rtt{
public:
    uint64_t first_rtt_sample = 0;
    uint64_t latest_rtt       = 0;
    uint64_t min_rtt          = UINT64_MAX;
    uint64_t smoothed_rtt     = 333000;
    uint64_t rttvar           = 166500;
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

struct quic_packet_meta{
    uint64_t pn;
    bool ack_eliciting;
    bool in_flight;
    size_t sent_bytes;
    uint64_t sent_time;
};

struct quic_packet_pn{
    quic_packet_meta meta;
    std::list<quic_frame*> frames;
};


class pn_namespace{
    std::function<int(uint64_t number, uint64_t ack, const void* body, size_t len)> sent;
    uint64_t current_pn     = 0;
public:
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
    std::list <quic_frame*>    lost_frames;
    pn_namespace(char name, std::function<int(uint64_t number, uint64_t ack, const void* body, size_t len)> sent);
    uint64_t PendAck();
    std::list<quic_packet_meta> DetectAndRemoveAckedPackets(const quic_ack* ack, Rtt* rtt, uint64_t max_delay_us);
    std::list<quic_packet_pn> DetectAndRemoveLostPackets(Rtt* rtt);
    void clear();
    int sendPacket();
    ~pn_namespace();
};

class QuicQos {
    size_t pto_count = 0;
    size_t bytes_in_flight = 0;
    size_t congestion_window = kInitialWindow;
    uint64_t congestion_recovery_start_time = 0;
    uint64_t ssthresh = UINT64_MAX;
    uint64_t last_receipt_ack_time = 0;
    pn_namespace* pns[3];
    bool isServer = false;
    Job* loss_timer = nullptr;
    void OnLossDetectionTimeout(pn_namespace* pn);
    Job* packet_tx = nullptr;
    void sendPacket();
    std::function<void(pn_namespace*, quic_frame*)> resendFrames;

    bool PeerCompletedAddressValidation();
    void SetLossDetectionTimer();
    void OnCongestionEvent(uint64_t sent_time);
    void OnPacketsLost(pn_namespace*pn, const std::list<quic_packet_pn>& lost_packets);
    void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets);
public:
    Rtt    rtt;
    uint64_t his_max_ack_delay = 0;
    QuicQos(bool isServer,
           std::function<int(OSSL_ENCRYPTION_LEVEL level, uint64_t number, uint64_t ack, const void* body, size_t len)> sent,
           std::function<void(pn_namespace*, quic_frame*)> resendFrames);
    ~QuicQos();
    pn_namespace* GetNamespace(OSSL_ENCRYPTION_LEVEL level);
    void GetKey(OSSL_ENCRYPTION_LEVEL level);
    void DropKey(OSSL_ENCRYPTION_LEVEL level);

    void handleFrame(OSSL_ENCRYPTION_LEVEL level, uint64_t number, const quic_frame* frame);
    void PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame);;
    void PushFrame(pn_namespace* pn, quic_frame* frame);
};

#endif //SPROXY_QUIC_QOS_H
