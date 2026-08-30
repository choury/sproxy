//
// Created by choury on 2026/8/29.
//

#include "quic_cubic.h"
#include "quic_reno.h"  // kPersistentCongestionThreshold

#include <inttypes.h>
#include <math.h>

QuicCubic::QuicCubic(bool isServer, const send_func& sent,
                     std::function<void(pn_namespace*, quic_frame)> resendFrames):
        QuicQos(isServer, sent, resendFrames) {
}

ssize_t QuicCubic::windowLeft() const {
    return (ssize_t)congestion_window - (ssize_t)bytes_in_flight;
}

size_t QuicCubic::cubicTarget(uint64_t now) const {
    // RFC 9438 4.2: W_cubic(t) = C*(t-K)^3 + W_max, 窗口以 MSS 为单位。
    // 有意用 t 而非 RFC 的 t+RTT: 无 pacing 时前瞻会放大突发, RTT 虚高时
    // 前瞻过头形成正反馈; 用 t 恒定落后曲线约一个 RTT, 偏保守
    double t = (now - epoch_start_time) / 1000000.0;
    double target = kCubicC * (t - k_epoch) * (t - k_epoch) * (t - k_epoch) + w_max;
    return target * max_datagram_size;
}

void QuicCubic::OnCongestionEvent(uint64_t sent_time) {
    // No reaction if already in a recovery period.
    if (sent_time <= congestion_recovery_start_time){
        return;
    }
    // Enter recovery period.
    uint64_t now = getutime();
    congestion_recovery_start_time = now;
    double cwnd_pkts = congestion_window / (double)max_datagram_size;
    w_prior = congestion_window; // cwnd_prior: 最近一次缩减前的窗口
    // Fast convergence: 未涨回上次 W_max 就再次丢包说明容量变小,
    // 将 W_max 下移到均值, 下个周期在更低处收敛
    if (cwnd_pkts < w_max) {
        w_max = cwnd_pkts * (1 + kCubicBeta) / 2;
    } else {
        w_max = cwnd_pkts;
    }
    congestion_window = std::max<size_t>(congestion_window * kCubicBeta, kMinimumWindow);
    ssthresh = congestion_window;
    // K = cbrt(W_max*(1-beta)/C), 从缩减点增长回 W_max 所需时间
    k_epoch = cbrt(w_max * (1 - kCubicBeta) / kCubicC);
    epoch_start_time = now;
    w_est = congestion_window;
    LOGD(DQUIC, "cubic cut congestion_window from %zd to %zd, w_max: %.1f\n",
         (size_t)(cwnd_pkts * max_datagram_size), (size_t)ssthresh, w_max);
}

void QuicCubic::OnPacketsLost(pn_namespace* ns, std::list<quic_packet_pn>& lost_packets) {
    uint64_t sent_time_of_last_loss = 0;
    uint64_t earliest_lost_time = UINT64_MAX;
    uint64_t latest_lost_time   = 0;

    // Remove lost packets from bytes_in_flight and collect timestamps for
    // both immediate congestion reaction and persistent congestion detection.
    for (auto& lost_packet : lost_packets) {
        if (lost_packet.meta.in_flight) {
            bytes_in_flight -= lost_packet.meta.sent_bytes;
            sent_time_of_last_loss = std::max(sent_time_of_last_loss, lost_packet.meta.sent_time);
        }
        for(auto& frame: lost_packet.frames){
            resendFrames(ns, std::move(frame));
        }
        if (lost_packet.meta.sent_time <= rtt.first_rtt_sample || !lost_packet.meta.ack_eliciting) {
            continue;
        }
        earliest_lost_time = std::min(earliest_lost_time, lost_packet.meta.sent_time);
        latest_lost_time   = std::max(latest_lost_time, lost_packet.meta.sent_time);
    }

    // Congestion event if in-flight packets were lost
    if (sent_time_of_last_loss != 0) {
        OnCongestionEvent(sent_time_of_last_loss);
    }

    // Reset the congestion window if the loss of these
    // packets indicates persistent congestion.
    // Only consider packets sent after getting an RTT sample.
    if (rtt.first_rtt_sample == 0 || earliest_lost_time == UINT64_MAX) {
        return;
    }
    uint64_t persistent_duration = (rtt.smoothed_rtt + std::max(4*rtt.rttvar, kGranularity) + his_max_ack_delay * 1000) *
                                   kPersistentCongestionThreshold;
    if (latest_lost_time - earliest_lost_time < persistent_duration) {
        return;
    }
    LOGD(DQUIC, "reset congestion_window to :%" PRIu64"\n", kMinimumWindow);
    // 持续拥塞: 容量估计彻底失效, 重置到最小窗口重新慢启动
    congestion_window = kMinimumWindow;
    ssthresh = UINT64_MAX;
    w_max = 0;
    k_epoch = 0;
    epoch_start_time = 0;
    w_prior = 0;
    w_est = congestion_window;
}

void QuicCubic::OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets) {
    uint64_t now = getutime();
    size_t sent_bytes = 0;
    // Evaluate cwnd-limited status once at ACK-event start.
    bool cwnd_limited = bytes_in_flight >= congestion_window;
    for (const auto &meta : acked_packets) {
        if (!meta.in_flight) {
            continue;
        }
        // Remove from bytes_in_flight.
        bytes_in_flight -= meta.sent_bytes;
        // Do not increase congestion_window if application
        // limited or flow control limited.
        if (!cwnd_limited || meta.app_limited) {
            continue;
        }

        // Do not increase congestion window in recovery period.
        if(meta.sent_time <= congestion_recovery_start_time){
            continue;
        }
        sent_bytes += meta.sent_bytes;
    }
    if (sent_bytes) {
        if (congestion_window < ssthresh) {
            // Slow start.
            congestion_window += sent_bytes;
        } else {
            // Congestion avoidance.
            if (epoch_start_time == 0) {
                // 没有活跃的 CUBIC 周期, 从当前时刻起算
                epoch_start_time = now;
            }
            // TCP 友好区域: W_est 为 Reno 等效窗口, 每轮增长 alpha*MSS,
            // 按确认字节占比折算到本次ACK; alpha 使稳态平均窗口与 Reno 相当,
            // W_est 越过 cwnd_prior 后升为 1(RFC 9438 4.3)
            double alpha = w_est >= w_prior ? 1.0 : kCubicAlphaAimd;
            w_est += alpha * max_datagram_size * sent_bytes / congestion_window;
            size_t target = cubicTarget(now);
            // RFC 9438 4.2 增速帽: 单轮目标最多比当前窗口高 50%,
            // 限制的是增速而非上限, 探测阶段可越过 1.5*W_max 继续爬升
            target = std::min(target, congestion_window + congestion_window / 2);
            target = std::max(target, w_est);
            LOGD(DQUIC, "cubic congestion_window: %zd, target: %zd, w_est: %zd, k_epoch: %.3fs\n",
                 congestion_window, target, w_est, k_epoch);
            if (target > congestion_window) {
                // 按本次确认字节占窗口的比例向目标窗口逼近
                congestion_window += sent_bytes * (target - congestion_window) / congestion_window;
            }
        }
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
    w_max = 0;
    k_epoch = 0;
    epoch_start_time = 0;
    w_prior = 0;
    w_est = congestion_window;
}
