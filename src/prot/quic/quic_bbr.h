//
// Created by choury on 24-6-6.
//

#ifndef SPROXY_QUIC_BBR_H
#define SPROXY_QUIC_BBR_H

#include "quic_qos.h"
#include <deque>

// 时间窗口内的最大/最小值跟踪器
// 用于跟踪BBR算法中的带宽和RTT测量值
class Twin {
    uint64_t window;  // 时间窗口大小（微秒）
    std::deque<std::pair<uint64_t, uint64_t>> content;  // (时间戳, 值) 对的双端队列
    
    // 清除过期的测量值
    void evict() {
        uint64_t now = getutime();
        while(content.size() > 1) {
            if(content.front().first + window < now) {
                content.pop_front();
                continue;
            }
            break;
        }
    }
public:
    Twin(uint64_t window): window(window) {
    }
    void setWindow(uint64_t window) {
        this->window = window;
    }
    // 插入新的测量值
    void insert(uint64_t value) {
        content.emplace_back(getutime(), value);
        evict();
    }
    // 获取时间窗口内的最大值（用于带宽测量）
    uint64_t max() const{
        uint64_t result = 0;
        for(const auto& [time, value] : content) {
            result = std::max(result, value);
        }
        return result;
    }
    // 获取时间窗口内的最小值（用于RTT测量）
    uint64_t min() const{
        uint64_t result = UINT64_MAX;
        for(const auto& p : content) {
            result = std::min(result, p.second);
        }
        return result;
    }

    void clear() {
        content.clear();
    }
};

// BBR算法的四个核心状态
// 每个状态对应不同的发送策略和拥塞控制目标
enum bbr_mode {
    BBR_STARTUP,    // 启动阶段：快速探测管道容量，以高增益发送
    BBR_DRAIN,      // 排空阶段：排空启动阶段创建的队列积压
    BBR_PROBE_BW,   // 带宽探测：周期性探测可用带宽的变化
    BBR_PROBE_RTT,  // RTT探测：定期降低发送量以测量最小RTT
};

class QuicBBR: public QuicQos {
    Twin rtProp;    // 用来跟踪最小RTT，单位是us
    Twin btlBw;     // 用来跟踪最大带宽，单位是 bytes/s

    bbr_mode mode = BBR_STARTUP;            // 当前BBR状态
    size_t pacing_gain_count = 0;           // PROBE_BW 的pacing状态轮次
    uint64_t pacing_round_start_time = 0;   // pacing当前轮开始时间
    uint64_t probe_rtt_start_time = 0;      // PROBE_RTT状态开始时间
    uint64_t min_rtt_stamp = 0;             // 最小RTT最后更新时间
    uint64_t full_bw = 0;                   // 满带宽估计值
    size_t full_bw_count = 0;               // 满带宽检测计数器
    
    
    // BBR算法核心函数
    uint32_t cwnd_gain() const;         // 计算拥塞窗口增益因子(整数,已乘BBR_UNIT)
    uint32_t pacing_gain() const;       // 计算发送速率增益因子(整数,已乘BBR_UNIT)
    
    // BBR v1状态机函数
    void EnterStartup();               // 进入STARTUP状态
    void EnterDrain();                 // 进入DRAIN状态
    void EnterProbeBW();               // 进入PROBE_BW状态
    void EnterProbeRTT();              // 进入PROBE_RTT状态
    void CheckCyclePhase();            // 检查PROBE_BW阶段循环
    void CheckDrainCondition();        // 检查DRAIN状态退出条件
    void CheckProbeRTTCondition();     // 检查是否需要进入PROBE_RTT
    void UpdateBBRState();             // 更新BBR状态机
    bool IsFullBandwidthReached();     // 检查是否达到满带宽
    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets, uint64_t ack_delay_us) override;
    virtual void OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) override;
    virtual void OnCongestionEvent(uint64_t sent_time) override;

public:
    QuicBBR(bool isServer, send_func sent, std::function<void(pn_namespace*, quic_frame*)> resendFrames);
    [[nodiscard]] virtual ssize_t windowLeft() const override;
};

#endif //SPROXY_QUIC_BBR_H
