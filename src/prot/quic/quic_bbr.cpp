//
// Created by choury on 24-6-6.
//
#include "quic_bbr.h"


// 单位转换常量
#define TIME_US_TO_MS  1000               // 微秒到毫秒转换因子
#define TIME_US_TO_S   1000000            // 微秒到秒转换因子  
#define BANDWIDTH_INIT 100000000          // 带宽值100MB/s -> bytes/s

// BBR算法常量定义
#define BBR_UNIT 1000                        // BBR增益计算的基础单位
#define BBR_HIGH_GAIN_VALUE (2885)           // 启动阶段的高增益因子 (2/ln(2) ≈ 2.885x)
#define BBR_DRAIN_GAIN_VALUE (347)           // 排空阶段的增益因子 (ln(2)/2 ≈ 0.347x)
#define BBR_CWND_GAIN_PROBE_BW (2000)        // PROBE_BW阶段拥塞窗口增益 (2.0x)
#define BBR_PROBE_RTT_CWND_GAIN (500)        // PROBE_RTT阶段拥塞窗口增益 (0.5x)

// BBR状态转换常量
#define BBR_FULL_BW_REACH_COUNT 3            // 检测满带宽需要的轮数
#define BBR_FULL_BW_THRESH (1250)            // 满带宽检测阈值 (1.25x)
#define BBR_MIN_RTT_WIN_SEC 10               // 最小RTT窗口时间（秒）
#define BBR_PROBE_RTT_MIN_TIME (200000)      // PROBE_RTT最小持续时间（200ms）

// PROBE_BW阶段的增益周期，用于周期性探测带宽变化
// 这个数组定义了8个阶段的循环：
// 1. 1.25x: 探测更多可用带宽
// 2. 0.75x: 排空队列或让出带宽给其他流
// 3-8. 1.0x: 在1.0倍带宽上巡航，充分利用管道但不创建过多队列
static const int pacing_gain_array[] = {
        BBR_UNIT * 5 / 4,    // 1.25x: 探测更多可用带宽
        BBR_UNIT * 3 / 4,    // 0.75x: 排空队列或让出带宽
        BBR_UNIT, BBR_UNIT, BBR_UNIT,    // 1.0x: 巡航阶段，充分利用管道
        BBR_UNIT, BBR_UNIT, BBR_UNIT     // 继续巡航，不创建过多队列
};

QuicBBR::QuicBBR(bool isServer, send_func sent, std::function<void(pn_namespace *, quic_frame *)> resendFrames):
        QuicQos(isServer, sent, resendFrames), 
        rtProp(10 * TIME_US_TO_S),  // RTT测量器，10秒时间窗口
        btlBw(10 * TIME_US_TO_S)    // 带宽测量器，10秒时间窗口
{
    // 初始化RTT估计值为1秒。这个值会在第一个RTT测量后被替换
    rtProp.insert(TIME_US_TO_S); // 1秒 初始RTT估计
    
    // 初始化时间戳
    uint64_t now = getutime();
    last_sent_time = now - TIME_US_TO_S; //避免初始状态窗口为0
    min_rtt_stamp = now;
    pacing_round_start_time = now;
    EnterStartup();
}


// 计算当前状态下的拥塞窗口增益因子
// 这个因子用于计算目标拥塞窗口大小 = BDP * cwnd_gain / BBR_UNIT
uint32_t QuicBBR::cwnd_gain() const {
    switch(mode){
    // 开始阶段使用高增益快速填充管道
    case BBR_STARTUP:
    case BBR_DRAIN:
        return BBR_HIGH_GAIN_VALUE;
    case BBR_PROBE_RTT:
        // PROBE_RTT阶段使用最小窗口探测最小RTT
        return BBR_PROBE_RTT_CWND_GAIN;
    default:
        // PROBE_BW阶段使用中等增益保持稳定
        return BBR_CWND_GAIN_PROBE_BW;
    }
}

// 计算当前状态下的发送速率增益因子
// 这个因子用于计算目标发送速率 = 带宽 * pacing_gain / BBR_UNIT
uint32_t QuicBBR::pacing_gain() const {
    switch(mode){
    case BBR_STARTUP:
        // STARTUP阶段使用高增益快速探测带宽
        return BBR_HIGH_GAIN_VALUE;
    case BBR_DRAIN:
        // DRAIN阶段使用低增益排空队列
        return BBR_DRAIN_GAIN_VALUE;
    case BBR_PROBE_BW:
        // PROBE_BW阶段使用循环增益探测带宽变化
        return pacing_gain_array[pacing_gain_count % 
                (sizeof(pacing_gain_array)/sizeof(pacing_gain_array[0]))];
    default:
        // 其他阶段使用标准增益
        return BBR_UNIT;
    }
}

// 处理数据包被确认的事件
// 这是BBR算法的核心，用于更新带宽和RTT估计
void QuicBBR::OnPacketsAcked(const std::list<quic_packet_meta> &acked_packets) {
    uint64_t now = getutime();
    const quic_packet_meta* packet_first = nullptr;
    
    // 处理所有被确认的包
    for (const auto& packet : acked_packets) {
        delivered_bytes += packet.sent_bytes;
        if(packet_first == nullptr && packet.ack_eliciting) {
            packet_first = &packet;
        }

        // 只有in_flight的包才需要从bytes_in_flight中减去
        if (packet.in_flight) {
            bytes_in_flight -= packet.sent_bytes;
        }
    }
    
    // 更新BBR的最小RTT估计（使用基类已经计算好的RTT）
    if (packet_first) {
        // 更新最小RTT时间戳
        if (rtt.latest_rtt <= rtProp.min()) {
            min_rtt_stamp = now;
        }
        rtProp.insert(rtt.latest_rtt);
        uint64_t delivered_time = now - packet_first->sent_time ;
        size_t delta_delivered_bytes = delivered_bytes - packet_first->delivered_bytes;
        size_t delivery_rate = delta_delivered_bytes * TIME_US_TO_S / delivered_time;
        if(!packet_first->app_limited || delivery_rate >= btlBw.max()) {
            btlBw.insert(delivery_rate);
        }
        if(packet_first->app_limited) {
            full_bw = 0;
            full_bw_count = 0;
        }
        LOGD(DQUIC, "BBR latest_rtt=%.3fms, delivered_time=%.3fms, delivered_bytes=%zd, delivered_rate=%zd, app_limited=%s\n", 
            rtt.latest_rtt/(double)TIME_US_TO_MS, delivered_time/(double)TIME_US_TO_MS, 
            delta_delivered_bytes, delivery_rate, packet_first->app_limited?"true":"false");
    }
    
    // 更新BBR状态机
    UpdateBBRState();

    if(has_packet_been_congested && windowLeft() >= (int)max_datagram_size){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 2);
    }
    LOGD(DQUIC, "BBR mode=%d, btlBw=%d, rtProp=%d, pacing_gain_count=%zd, since_last_sent=%.3fms, bytes_in_flight=%zd\n", 
        mode, (int)btlBw.max(), (int)rtProp.min(), pacing_gain_count, (now - last_sent_time)/(double)TIME_US_TO_MS, bytes_in_flight);
}

// BBR丢包处理：与CUBIC不同，BBR对丢包的反应更温和，但需要重传这些包
void QuicBBR::OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) {
    // BBR算法对丢包的反应较为温和，主要是重传丢失的包
    // 不像CUBIC那样激进地减少拥塞窗口
    
    for (const auto& lost_packet : lost_packets) {
        if (lost_packet.meta.in_flight) {
            bytes_in_flight -= lost_packet.meta.sent_bytes;
        }
        
        // 重传丢失的帧
        for (auto frame : lost_packet.frames) {
            resendFrames(ns, frame);
        }
    }
    
    // 在STARTUP阶段，如果遇到丢包，可能需要更保守一些
    if (mode == BBR_STARTUP && !lost_packets.empty()) {
        // 可以考虑降低增长速度，但BBR通常不会因为少量丢包就退出STARTUP
        // 这里保持简单的实现
    }
}

ssize_t QuicBBR::windowLeft() const {
    size_t window = kInitialWindow;
    if(btlBw.max()) {
        uint64_t bdp = btlBw.max() * rtProp.min() / TIME_US_TO_S;
        window = bdp * cwnd_gain() / BBR_UNIT;
    }
    if(window + bytes_in_flight < kMinimumWindow) {
        return kMinimumWindow - bytes_in_flight;
    }
    return window;
}

ssize_t QuicBBR::sendWindow() const {
    uint64_t now = getutime();
    uint64_t btl_bw = btlBw.max() ?: BANDWIDTH_INIT;
    uint64_t pacing_rate = std::max(btl_bw * pacing_gain() / BBR_UNIT, kMinimumWindow * TIME_US_TO_S / rtt.smoothed_rtt);
    size_t pacing_window = std::min(now - last_sent_time, rtt.smoothed_rtt + 1000) * pacing_rate / TIME_US_TO_S;
    if (mode == BBR_STARTUP) {
        // STARTUP阶段使用无限大窗口，仅依靠pacing控制
        return pacing_window;
    }else {
        return std::min(windowLeft(), (ssize_t)pacing_window);
    }
}

// BBR v1状态机函数实现

void QuicBBR::EnterStartup() {
    mode = BBR_STARTUP;
    pacing_gain_count = 0;
    full_bw = 0;
    full_bw_count = 0;
    btlBw.clear();
}

void QuicBBR::EnterDrain() {
    mode = BBR_DRAIN;
    pacing_gain_count = 0;
    CheckDrainCondition();
}

void QuicBBR::EnterProbeBW() {
    mode = BBR_PROBE_BW;
    pacing_gain_count = 0;
}

void QuicBBR::EnterProbeRTT() {
    mode = BBR_PROBE_RTT;
    probe_rtt_start_time = getutime();
}

bool QuicBBR::IsFullBandwidthReached() {
    uint64_t current_bw = btlBw.max();
    
    // 如果当前带宽比之前记录的满带宽高出25%，说明还在增长
    if (current_bw * BBR_UNIT >= full_bw * BBR_FULL_BW_THRESH) {
        full_bw = current_bw;
        full_bw_count = 0;
        return false;
    }
    
    // 如果连续3轮带宽增长不超过25%，认为达到满带宽
    full_bw_count++;
    return full_bw_count >= BBR_FULL_BW_REACH_COUNT;
}

void QuicBBR::CheckCyclePhase() {
    if (mode != BBR_PROBE_BW) {
        return;
    }
    
    uint64_t now = getutime();
    // 每轮结束时推进到下一个增益阶段
    if (last_sent_time > pacing_round_start_time &&  now - pacing_round_start_time >= rtProp.min()) {
        pacing_gain_count ++;
        pacing_round_start_time = now;
    }
}

void QuicBBR::CheckDrainCondition() {
    if (mode != BBR_DRAIN) {
        return;
    }
    
    // 当in-flight字节数降到BDP以下时，退出DRAIN状态
    uint64_t bdp = btlBw.max() * rtProp.min() / TIME_US_TO_S;
    if (bytes_in_flight <= bdp) {
        EnterProbeBW();
    }
}

void QuicBBR::CheckProbeRTTCondition() {
    uint64_t now = getutime();

    if(mode == BBR_PROBE_RTT) {
        // 在PROBE_RTT状态至少持续200ms
        // 如果已经完成一轮最小窗口发送，可以退出（简化实现：基于时间）
        if(now - probe_rtt_start_time >= BBR_PROBE_RTT_MIN_TIME 
            && last_sent_time > probe_rtt_start_time 
            && now - last_sent_time > rtProp.min()) {
            min_rtt_stamp = now;  // 重置最小RTT时间戳
            if (full_bw == 0 || !IsFullBandwidthReached()) {
                EnterStartup();
            } else {
                EnterProbeBW();
            }
        }
    } else {
        // 如果最小RTT测量值超过10秒没有更新，需要进入PROBE_RTT
        if (now - min_rtt_stamp >= BBR_MIN_RTT_WIN_SEC * TIME_US_TO_S) {
            EnterProbeRTT();
        }
    }
}

void QuicBBR::UpdateBBRState() {
    // 根据当前状态执行相应的状态转换检查
    switch (mode) {
    case BBR_STARTUP:
        // 检查是否达到满带宽，如果是则进入DRAIN状态
        if (IsFullBandwidthReached()) {
            EnterDrain();
        }
        break;
        
    case BBR_DRAIN:
        CheckDrainCondition();
        break;
        
    case BBR_PROBE_BW:
        CheckCyclePhase();
        break;
        
    case BBR_PROBE_RTT:
        // PROBE_RTT状态的退出条件在CheckProbeRTTCondition中处理
        break;
    }
    
    // 所有状态都需要检查是否进入PROBE_RTT
    CheckProbeRTTCondition();
}

void QuicBBR::OnCongestionEvent(uint64_t /*sent_time*/) {
    // ECN marks don't directly affect BBR's bandwidth or RTT measurements
    // but indicate network congestion, so we might want to be more conservative
    // This is a simplified implementation - more sophisticated BBR versions
    // might adjust pacing rates based on ECN feedback
}
