//
// Created by choury on 2025/6/8.
//

#ifndef SPROXY_QUIC_CUBIC_H
#define SPROXY_QUIC_CUBIC_H

#include "quic_qos.h"

const uint64_t kInitialWindow = 14720;
const uint64_t kMinimumWindow = 2 * max_datagram_size;
const double  kLossReductionFactor = 0.5;
const double  kPersistentCongestionThreshold = 3;

class QuicCubic: public QuicQos {
protected:
    size_t congestion_window = kInitialWindow;
    uint64_t congestion_recovery_start_time = 0;
    uint64_t ssthresh = UINT64_MAX;

    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets, uint64_t ack_delay_us) override;
    virtual void OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) override;
    virtual void OnCongestionEvent(uint64_t sent_time) override;

public:
    QuicCubic(bool isServer, const send_func& sent,
             std::function<void(pn_namespace*, quic_frame*)> resendFrames);
    [[nodiscard]] virtual ssize_t windowLeft() const override;
};

#endif //SPROXY_QUIC_CUBIC_H