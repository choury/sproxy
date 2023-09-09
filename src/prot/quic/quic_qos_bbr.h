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

class QuicQosBBR: public QuicQos {
    Twin rtProp;
    Twin btlBw;

    size_t pacing_gain_count = 0;
    uint64_t last_sent_time = 0;
public:
    QuicQosBBR(bool isServer, send_func sent, std::function<void(pn_namespace*, quic_frame*)> resendFrames);

    virtual void sendPacket() override;
    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets, uint64_t ack_delay_us) override;
};


#endif //SPROXY_QUIC_QOS_BBR_H
