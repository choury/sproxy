//
// Created by choury on 2026/8/29.
//

#ifndef SPROXY_QUIC_CUBIC_H
#define SPROXY_QUIC_CUBIC_H

#include "quic_qos.h"

// CUBIC 拥塞控制参数, 参考 RFC 9438
const double kCubicBeta = 0.7;  // 丢包时窗口缩减因子
const double kCubicC    = 0.4;  // 立方函数缩放因子
// TCP 友好区域增速因子: 3*(1-beta)/(1+beta), 使稳态平均窗口与 Reno 相当
const double kCubicAlphaAimd = 3 * (1 - kCubicBeta) / (1 + kCubicBeta);

class QuicCubic: public QuicQos {
protected:
    size_t congestion_window = kInitialWindow;
    uint64_t congestion_recovery_start_time = 0;
    uint64_t ssthresh = UINT64_MAX;

    // CUBIC 周期状态, 自上次窗口缩减起算
    double w_max = 0;              // 缩减前达到的最大窗口(MSS)
    double k_epoch = 0;            // 从缩减点增长回 W_max 所需时间(秒)
    uint64_t epoch_start_time = 0; // 当前周期起始时间
    size_t w_prior = 0;            // 最近一次缩减前的窗口(字节), 即 cwnd_prior
    size_t w_est = 0;              // TCP 友好区域的 Reno 等效窗口(字节)

    // W_cubic(t) = C*(t-K)^3 + W_max, t 为距周期开始的秒数, 返回目标窗口(字节)
    size_t cubicTarget(uint64_t now) const;

    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets) override;
    virtual void OnPacketsLost(pn_namespace* ns, std::list<quic_packet_pn>& lost_packets) override;
    virtual void OnCongestionEvent(uint64_t sent_time) override;
    virtual void Migrated() override;
public:
    QuicCubic(bool isServer, const send_func& sent,
              std::function<void(pn_namespace*, quic_frame)> resendFrames);
    [[nodiscard]] virtual ssize_t windowLeft() const override;
};

#endif //SPROXY_QUIC_CUBIC_H
