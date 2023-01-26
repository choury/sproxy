//
// Created by 周威 on 2023/1/8.
//

#include "quic_qos_bbr.h"


#define BBR_UNIT 1000


/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int pacing_gain_array[] = {
        BBR_UNIT * 5 / 4,	/* probe for more available bw */
        BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
        BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
        BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};

QuicQosBBR::QuicQosBBR(bool isServer, send_func sent, std::function<void(pn_namespace *, quic_frame *)> resendFrames):
                        QuicQos(isServer, sent, resendFrames), rtProp(1000*1000), btlBw(1000*1000) {
    btlBw.insert(1000); //1M/s
    rtProp.insert(1e6); //1s
    congestion_window = SIZE_MAX;
}


double QuicQosBBR::cwnd_gain() {
    switch(mode){
    case BBR_STARTUP:
        return 2;
    default:
        return 1.2;
    }
}

double QuicQosBBR::pacing_gain() {
    switch(mode){
    case BBR_STARTUP:
        return 2.77;
    default:
        return 0;
    }
}

#if 0
BBRCheckStartupDone():
    BBRCheckStartupFullBandwidth()
    BBRCheckStartupHighLoss()
    if (BBR.state == Startup and BBR.filled_pipe)
      BBREnterDrain()
#endif
void QuicQosBBR::BBRCheckStartupDone() {
    BBRCheckStartupFullBandwidth();
    BBRCheckStartupDone();
    if(mode == BBR_STARTUP && filled_pipe) {
        mode = BBR_DRAIN;
    }
}

#if 0
BBRCheckStartupFullBandwidth():
    if BBR.filled_pipe or
       !BBR.round_start or rs.is_app_limited
      return  /* no need to check for a full pipe now */
    if (BBR.max_bw >= BBR.full_bw * 1.25)  /* still growing? */
      BBR.full_bw = BBR.max_bw    /* record new baseline level */
      BBR.full_bw_count = 0
      return
    BBR.full_bw_count++ /* another round w/o much growth */
    if (BBR.full_bw_count >= 3)
      BBR.filled_pipe = true
#endif
void QuicQosBBR::BBRCheckStartupFullBandwidth() {
}

void QuicQosBBR::sendPacket() {
    uint64_t bdp = btlBw.max() * rtProp.min()/1000;
    if(bytes_in_flight > 12 * bdp/10) {
        LOGD(DQUIC, "sendPacket bytes_in_flight: %zd, bdp: %u, skip now\n", bytes_in_flight, (unsigned int)bdp);
        return;
    }
    bool has_pending_packet = false;
    uint64_t now = getutime();
    size_t pacing_gain = pacing_gain_array[(pacing_gain_count++) % (sizeof(pacing_gain_array)/ sizeof(pacing_gain_array[1]))];
    size_t window = std::min((now - last_sent_time) * pacing_gain * btlBw.max() / BBR_UNIT / 1000, 12*bdp/10 - bytes_in_flight);
    LOGD(DQUIC, "sendPacket pto_count: %zu, btlBw: %d, minRtt: %.2fms, window: %zd, bytes_in_flight: %zd\n",
         pto_count, (int)btlBw.max(), rtProp.min()/1000.0, window, bytes_in_flight);

    for(auto &p: pns) {
        if (!p->hasKey) {
            continue;
        }
        p->PendAck();
        if (p->pend_frames.empty()) {
            continue;
        }

        if(pto_count > 0) {
            //如果在丢包探测阶段，只发送一个探测包
            last_sent_time = now;
            bytes_in_flight += p->sendPacket(max_datagram_size, delivered_bytes, delivered_time);
            return;
        }
        if(window < max_datagram_size) {
            //拥塞窗口已满，等待收到ack后触发发送
            break;
        }
        auto ret = p->sendPacket(window, delivered_bytes, delivered_time);
        if(ret > 0) {
            last_sent_time = now;
            bytes_in_flight += ret;
            window -= ret;
        }

        if(!p->pend_frames.empty()) {
            has_pending_packet = true;
        }
    }
    has_packet_been_congested = has_pending_packet;
    if(has_pending_packet && window > max_datagram_size) {
        //很大可能是udp的buffer满了，等一会重试
        packet_tx  = UpdateJob(packet_tx, std::bind(&QuicQosBBR::sendPacket, this), 0);
    }
}

void QuicQosBBR::OnPacketsAcked(const std::list<quic_packet_meta> &acked_packets, uint64_t ack_delay_us) {
    rtProp.insert(rtt.latest_rtt + ack_delay_us);
    delivered_time = getutime();
    for(const auto& packet : acked_packets) {
        delivered_bytes += packet.sent_bytes;
        uint64_t delivery_rate  =  (delivered_bytes - packet.delivered_bytes) * 1000/ (delivered_time - packet.delivered_time);
        if(!packet.app_limited || delivery_rate > btlBw.max()) {
            btlBw.insert(delivery_rate);
        }
        if(!packet.in_flight) {
            continue;
        }
        bytes_in_flight -= packet.sent_bytes;
        LOGD(DQUIC, "delivery_rate: %d, bytes: %zd, time: %.2fms, bytes_in_flight: %zd\n",
             (int)delivery_rate, delivered_bytes - packet.delivered_bytes, (delivered_time - packet.delivered_time)/1000.0, bytes_in_flight);
    }
    uint64_t bdp = btlBw.max() * rtProp.min()/1000;
    if(has_packet_been_congested && bytes_in_flight < 12*bdp/10){
        packet_tx = UpdateJob(packet_tx, [this]{sendPacket();} , 0);
    }
}
