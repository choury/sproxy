//
// Created by 周威 on 2023/1/8.
//

#ifndef SPROXY_QUIC_QOS_BBR_H
#define SPROXY_QUIC_QOS_BBR_H

#include "quic_qos.h"
#include <list>

class Twin {
    uint64_t window;
    std::list<std::pair<uint64_t, uint64_t>> content;
    void evict() {
        uint64_t now = getutime();
        while(content.size() > 1 && content.front().first + window < now) {
            content.pop_front();
        }
    }
public:
    Twin(uint64_t window): window(window) {
    }
    void setWindow(uint64_t window) {
        this->window = window;
    }
    void insert(uint64_t value) {
        content.emplace_back(getutime(), value);
    }
    uint64_t max() {
        evict();
        uint64_t result = 0;
        for(const auto& p : content) {
            result = std::max(result, p.second);
        }
        return result;
    }
    uint64_t min() {
        evict();
        uint64_t result = UINT64_MAX;
        for(const auto& p : content) {
            result = std::min(result, p.second);
        }
        return result;
    }
};

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
    BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
    BBR_DRAIN,	/* drain any queue created during startup */
    BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
    BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};

class QuicQosBBR: public QuicQos {
    Twin rtProp;
    Twin btlBw;

    bbr_mode mode = BBR_STARTUP;
    size_t delivered_bytes = 0;
    uint64_t delivered_time = 0;
    size_t pacing_gain_count = 0;
    uint64_t last_sent_time = 0;
    bool filled_pipe = false;
    size_t full_bw = 0;
    int full_bw_count = 0;

    double cwnd_gain();
    double pacing_gain();
    void BBRCheckStartupDone();
    void BBRCheckStartupFullBandwidth();
    void BBRCheckStartupHighLoss();
public:
    QuicQosBBR(bool isServer, send_func sent, std::function<void(pn_namespace*, quic_frame*)> resendFrames);

    virtual void sendPacket() override;
    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets, uint64_t ack_delay_us) override;
};


#endif //SPROXY_QUIC_QOS_BBR_H
