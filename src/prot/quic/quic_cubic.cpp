//
// Created by choury on 2025/6/8.
//

#include "quic_cubic.h"

#include <inttypes.h>

QuicCubic::QuicCubic(bool isServer, const send_func& sent,
                     std::function<void(pn_namespace*, quic_frame*)> resendFrames):
        QuicQos(isServer, sent, resendFrames) {
}

ssize_t QuicCubic::windowLeft() const {
    return (int)congestion_window - (int)bytes_in_flight;
}

void QuicCubic::OnCongestionEvent(uint64_t sent_time) {
    // No reaction if already in a recovery period.
    if (sent_time <= congestion_recovery_start_time){
        return;
    }
    // Enter recovery period.
    congestion_recovery_start_time = getutime();
    ssthresh = congestion_window * kLossReductionFactor;
    LOGD(DQUIC, "cut congestion_window from %zd to %zd\n", congestion_window, (size_t)ssthresh);
    congestion_window = std::max(ssthresh, kMinimumWindow);
    //TODO: A packet can be sent to speed up loss recovery.
}

void QuicCubic::OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) {
    uint64_t sent_time_of_last_loss = 0;
    // Remove lost packets from bytes_in_flight.
    for(const auto& lost_packet: lost_packets) {
        if (lost_packet.meta.in_flight) {
            bytes_in_flight -= lost_packet.meta.sent_bytes;
            sent_time_of_last_loss = std::max(sent_time_of_last_loss, lost_packet.meta.sent_time);
        }
        for(auto frame: lost_packet.frames){
            resendFrames(ns, frame);
        }
    }
    // Congestion event if in-flight packets were lost
    if (sent_time_of_last_loss != 0) {
        OnCongestionEvent(sent_time_of_last_loss);
    }

    // Reset the congestion window if the loss of these
    // packets indicates persistent congestion.
    // Only consider packets sent after getting an RTT sample.
    if (rtt.first_rtt_sample == 0) {
        return;
    }
    size_t persistent_lost_count = 0;
    for(const auto& lost: lost_packets) {
        if (lost.meta.sent_time <= rtt.first_rtt_sample) {
            continue;
        }
        if (!lost.meta.ack_eliciting){
            continue;
        }
        persistent_lost_count ++;
    }
    if(persistent_lost_count < 2){
        return;
    }
    uint64_t persistent_duration = (rtt.smoothed_rtt + std::max(4*rtt.rttvar, kGranularity) + his_max_ack_delay) *
                                   kPersistentCongestionThreshold;
    if(getutime() - last_receipt_ack_time < persistent_duration){
        return;
    }
    LOGD(DQUIC, "reset congestion_window to :%" PRIu64"\n", kMinimumWindow);
    congestion_window = kMinimumWindow;
    congestion_recovery_start_time = 0;
}

void QuicCubic::OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets) {
    size_t sent_bytes = 0;
    for(auto meta: acked_packets){
        if(!meta.in_flight){
            continue;
        }
        // Remove from bytes_in_flight.
        bytes_in_flight -= meta.sent_bytes;
        // Do not increase congestion_window if application
        // limited or flow control limited.
        //TODO: check if it is application limited or flow control limited

        // Do not increase congestion window in recovery period.
        if(meta.sent_time <= congestion_recovery_start_time){
            continue;
        }
        sent_bytes += meta.sent_bytes;
    }
    if (congestion_window < ssthresh) {
        // Slow start.
        congestion_window += sent_bytes;
    } else {
        // Congestion avoidance.
        congestion_window += max_datagram_size * sent_bytes / congestion_window;
    }
    if(has_packet_been_congested){
        maySend(true);
    }
}

void QuicCubic::Migrated() {
    QuicQos::Migrated();
    congestion_window = kInitialWindow;
    congestion_recovery_start_time = 0;
    ssthresh = UINT64_MAX;
}
