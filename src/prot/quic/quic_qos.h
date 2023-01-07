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
#include <set>
#include <functional>

const uint64_t max_datagram_size = 1400;
const uint64_t kInitialWindow = 14720;
const uint64_t kMinimumWindow = 2 * max_datagram_size;
const uint64_t kPacketThreshold = 3;
const uint64_t kGranularity = 1000; // 1ms
const double  kLossReductionFactor = 0.5;
const double  kPersistentCongestionThreshold = 3;

#define QUIC_PACKET_NAMESPACE_INITIAL 0
#define QUIC_PACKET_NAMESPACE_HANDSHAKE 1
#define QUIC_PAKCET_NAMESPACE_APP 2


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

struct Rtt{
    uint64_t first_rtt_sample = 0;
    uint64_t latest_rtt       = 0;
    uint64_t min_rtt          = UINT64_MAX;
    uint64_t smoothed_rtt     = 333000;
    uint64_t rttvar           = 166500;
};


class pn_namespace;
class QuicQos {
    size_t pto_count = 0;
    size_t bytes_in_flight = 0;
    size_t congestion_window = kInitialWindow;
    uint64_t congestion_recovery_start_time = 0;
    uint64_t ssthresh = UINT64_MAX;
    uint64_t last_receipt_ack_time = 0;
    uint64_t his_max_ack_delay = 0;
    bool has_packet_been_congested = false;

    pn_namespace* pns[3];
    bool isServer = false;
    Job* loss_timer = nullptr;
    void OnLossDetectionTimeout(pn_namespace* ns);
    Job* packet_tx = nullptr;
    void sendPacket();
    std::function<void(pn_namespace*, quic_frame*)> resendFrames;
    std::function<void(int error)> ErrorHE;

    bool PeerCompletedAddressValidation();
    void SetLossDetectionTimer();
    void OnCongestionEvent(uint64_t sent_time);
    void OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets);
    void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets);
    pn_namespace* GetNamespace(OSSL_ENCRYPTION_LEVEL level);
public:
    Rtt    rtt;
    /*
    typedef std::function<int(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack,
            const void* body, size_t len, const std::set<uint64_t>& streams)>  send_func;
            */
    typedef std::function<std::list<quic_packet_pn>(OSSL_ENCRYPTION_LEVEL level,
                                           uint64_t pn, uint64_t ack,
                                           std::list<quic_frame*>& pend_frames, size_t window)> send_func;
    QuicQos(bool isServer, send_func sent,
           std::function<void(pn_namespace*, quic_frame*)> resendFrames,
           std::function<void(int error)> ErrorHE);
    ~QuicQos();
    void KeyGot(OSSL_ENCRYPTION_LEVEL level);
    void KeyLost(OSSL_ENCRYPTION_LEVEL level);
    //set ack_delay_exponent for app level
    void SetAckDelayExponent(uint64_t exponent);
    //set max_ack_delay for app level
    void SetMaxAckDelay(uint64_t delay);
    uint64_t GetLargestPn(OSSL_ENCRYPTION_LEVEL level);

    void handleFrame(OSSL_ENCRYPTION_LEVEL level, uint64_t number, const quic_frame* frame);
    void HandleRetry();
    void PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame);;
    void PushFrame(pn_namespace* ns, quic_frame* frame);
    void FrontFrame(pn_namespace* ns, quic_frame* frame);
    void SendNow();

    size_t mem_usage();
};

#endif //SPROXY_QUIC_QOS_H
