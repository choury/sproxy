//
// Created by 周威 on 2021/8/22.
//

#include "quic_qos.h"
#include <inttypes.h>
#include <assert.h>
#include <misc/util.h>
#include <inttypes.h>


static int get_packet_namespace(OSSL_ENCRYPTION_LEVEL level){
    switch(level){
    case ssl_encryption_initial:
        return QUIC_PACKET_NAMESPACE_INITIAL;
    case ssl_encryption_handshake:
        return QUIC_PACKET_NAMESPACE_HANDSHAKE;
    case ssl_encryption_early_data:
    case ssl_encryption_application:
        return QUIC_PAKCET_NAMESPACE_APP;
    }
    abort();
}



QuicQos::QuicQos(bool isServer, const send_func& sent,
           std::function<void(pn_namespace*, quic_frame*)> resendFrames):
            isServer(isServer), resendFrames(std::move(resendFrames)){
    pns[QUIC_PACKET_NAMESPACE_INITIAL] = new pn_namespace('I', [sent](auto&& v1, auto&& v2, auto&& v3, auto&& v4){
        return sent(ssl_encryption_initial, v1, v2, v3, v4);
    });
    pns[QUIC_PACKET_NAMESPACE_HANDSHAKE] = new pn_namespace('H',[sent](auto&& v1, auto&& v2, auto&& v3, auto&& v4){
        return sent(ssl_encryption_handshake, v1, v2, v3, v4);
    });
    pns[QUIC_PAKCET_NAMESPACE_APP] = new pn_namespace('A', [sent](auto&& v1, auto&& v2, auto&& v3, auto&& v4){
        return sent(ssl_encryption_application, v1, v2, v3, v4);
    });
}


QuicQos::~QuicQos() {
    DrainAll();
}

ssize_t QuicQos::windowLeft() const {
    return (int)congestion_window - (int)bytes_in_flight;
}

pn_namespace* QuicQos::GetNamespace(OSSL_ENCRYPTION_LEVEL level) {
    return pns[get_packet_namespace(level)];
}

void QuicQos::KeyGot(OSSL_ENCRYPTION_LEVEL level) {
    pns[get_packet_namespace(level)]->hasKey = true;
}


void QuicQos::KeyLost(OSSL_ENCRYPTION_LEVEL level) {
    auto pn = pns[get_packet_namespace(level)];
    for(auto& packet : pn->sent_packets) {
        assert(!packet.frames.empty());
        if(!packet.meta.in_flight) {
            continue;
        }
        bytes_in_flight -= packet.meta.sent_bytes;
    }
    pn->clear();
    pto_count = 0;
    SetLossDetectionTimer();
}

void QuicQos::SetAckDelayExponent(uint64_t exponent) {
    GetNamespace(ssl_encryption_application)->ack_delay_exponent = exponent;
}

void QuicQos::SetMaxAckDelay(uint64_t delay) {
    his_max_ack_delay = delay;
}

uint64_t QuicQos::GetLargestPn(OSSL_ENCRYPTION_LEVEL level) {
    auto ns = GetNamespace(level);
    if(ns->tracked_receipt_pns.latest_time == 0){
        return 0;
    }
    return GetNamespace(level)->tracked_receipt_pns.items.back().second;
}

bool QuicQos::PeerCompletedAddressValidation() {
    if(!isServer) {
        return true;
    }
    return pns[QUIC_PACKET_NAMESPACE_HANDSHAKE]->largest_acked_packet != UINT64_MAX ||
           pns[QUIC_PAKCET_NAMESPACE_APP]->hasKey;
}

void QuicQos::OnLossDetectionTimeout(pn_namespace* ns){
    uint64_t now = getutime();
    if(ns->loss_time < UINT64_MAX){
        LOGD(DQUIC, "loss timer expired for [%c], loss_time: %.2fms\n",
             ns->name, (now - ns->time_of_last_ack_eliciting_packet) / 1000.0);
        auto lost_packets = ns->DetectAndRemoveLostPackets(&rtt);
        //虽然rfc上说这里lost_packets不可能为空，但是实际上rtt是一直在变化的，这就导致两次算出来的loss_time不一致，
        //这样的话，当loss_time触发时，rtt可能已经变长，而据此算出的timeThreshold就会变大，此时之前触发loss的包
        //在这个周期内就会获取不到，因此可能出现lost_packets为空的情况
        if(!lost_packets.empty()) {
            OnPacketsLost(ns, lost_packets);
        }
    }else {
        //pto超时触发之前必定已经触发了loss_time，因此这里并不需要做丢包处理，只需要发探测包（ping）
        LOGD(DQUIC, "pto expired for [%c], pto_time: %.2fms, pto_count: %zd\n",
             ns->name, (now - ns->time_of_last_ack_eliciting_packet) / 1000.0, pto_count);
        pto_count++;
        FrontFrame(ns, new quic_frame{QUIC_FRAME_PING, {}});
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    }
    SetLossDetectionTimer();
}

void QuicQos::SetLossDetectionTimer() {
    uint64_t now = getutime();
    uint64_t timed_out = UINT64_MAX;
    bool has_eliciting_packet = false;
    pn_namespace* ns = nullptr;
    for(auto& p: pns){
        if(p->loss_time < timed_out){
            timed_out = p->loss_time;
            ns = p;
        }
        if(has_eliciting_packet){
            continue;
        }
        for(const auto& packet: p->sent_packets){
            assert(!packet.frames.empty());
            if(packet.meta.ack_eliciting){
                has_eliciting_packet = true;
                break;
            }
        }
    }
    if(ns){
        loss_timer = UpdateJob(std::move(loss_timer),
                               ([this, ns]{OnLossDetectionTimeout(ns);}),
                               (timed_out - now - 1) / 1000 + 1);
        return;
    }
    if(!has_eliciting_packet && PeerCompletedAddressValidation()){
        LOGD(DQUIC, "no packet to send, stop loss detection\n");
        loss_timer.reset(nullptr);
        return;
    }
    uint64_t pto = (rtt.smoothed_rtt + std::max(4 * rtt.rttvar, kGranularity) + his_max_ack_delay * 1000) << pto_count;
    if(!has_eliciting_packet){
        if(pns[QUIC_PACKET_NAMESPACE_HANDSHAKE]->hasKey) {
            loss_timer = UpdateJob(std::move(loss_timer),
                                   ([this, ns = pns[QUIC_PACKET_NAMESPACE_HANDSHAKE] ] {
                                       OnLossDetectionTimeout(ns);
                                   }), pto / 1000);
        }else{
            loss_timer = UpdateJob(std::move(loss_timer),
                                   ([this, ns = pns[QUIC_PACKET_NAMESPACE_INITIAL] ] {
                                       OnLossDetectionTimeout(ns);
                                   }), pto / 1000);
        }
        return;
    }
    for(auto& p: pns){
        if(!p->hasKey){
            continue;
        }
        has_eliciting_packet = false;
        for(const auto& packet: p->sent_packets){
            assert(!packet.frames.empty());
            if(packet.meta.ack_eliciting){
                has_eliciting_packet = true;
                break;
            }
        }
        if(!has_eliciting_packet){
            continue;
        }
        if(p->time_of_last_ack_eliciting_packet + pto < timed_out){
            timed_out = p->time_of_last_ack_eliciting_packet + pto;
            ns = p;
        }
    }
    assert(ns);
    loss_timer = UpdateJob(std::move(loss_timer),
                           ([this, ns]{OnLossDetectionTimeout(ns);}),
                           (timed_out - now - 1) / 1000 + 1);
}

void QuicQos::sendPacket() {
    bool has_pending_packet = false;
    bool has_in_flight = false;
    for(auto &p: pns){
        if(!p->hasKey){
            continue;
        }
        p->PendAck();
        if(p->pend_frames.empty()) {
            continue;
        }
        LOGD(DQUIC, "sendPacket, pto_count: %zu, congestion_window: %zd, bytes_in_flight: %zd, ssthresh: %" PRIu64"\n",
             pto_count, congestion_window, bytes_in_flight, ssthresh);
        if(pto_count > 0) {
            //如果在丢包探测阶段，只发送一个包
            bytes_in_flight += p->sendPacket(max_datagram_size, 0, 0);
            return;
        }else if(!p->pend_frames.empty() && congestion_window > bytes_in_flight + max_datagram_size) {
            bytes_in_flight += p->sendPacket(congestion_window - bytes_in_flight, 0, 0);
            has_in_flight = true;
        }
        if(!p->pend_frames.empty()){
            has_pending_packet = true;
            break;
        }
    }
    has_packet_been_congested = has_pending_packet;
    if(has_packet_been_congested && congestion_window > bytes_in_flight + max_datagram_size) {
        //很大可能是udp的buffer满了，等一会重试
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    }
    if(has_in_flight){
        SetLossDetectionTimer();
    }
}

void QuicQos::OnCongestionEvent(uint64_t sent_time) {
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

void QuicQos::OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) {
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

void QuicQos::OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets,  uint64_t) {
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
    if(has_packet_been_congested && congestion_window > bytes_in_flight + max_datagram_size){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    }
}

std::set<uint64_t> QuicQos::handleFrame(OSSL_ENCRYPTION_LEVEL level, uint64_t number, const quic_frame *frame) {
    pn_namespace* ns = this->GetNamespace(level);
    dumpFrame(">", ns->name, frame);
    if(!ns->hasKey){
        //key has dropped before handle it.
        return {};
    }
    ns->tracked_receipt_pns.Add(number);
    if(is_ack_eliciting(frame)){
        ns->should_ack = true;
    }
    //FIXME:
    // When a server is blocked by anti-amplification limits, receiving a datagram unblocks it,
    // even if none of the packets in the datagram are successfully processed.
    // In such a case, the PTO timer will need to be rearmed.
    std::set<uint64_t> streamIds;
    if(frame->type == QUIC_FRAME_ACK || frame->type == QUIC_FRAME_ACK_ECN){
        last_receipt_ack_time = getutime();
        uint64_t ack_delay_us;
        auto acked = ns->DetectAndRemoveAckedPackets(&frame->ack, &rtt, ack_delay_us, his_max_ack_delay * 1000);
        if(acked.empty()){
            return {};
        }
        for(auto& meta: acked){
            streamIds.insert(meta.streamIds.begin(), meta.streamIds.end());
        }

        if(frame->type == QUIC_FRAME_ACK_ECN && frame->ack.ecn_ce > ns->ecn_ce_counters) {
            // If the ECN-CE counter reported by the peer has increased,
            // this could be a new congestion event.
            ns->ecn_ce_counters = frame->ack.ecn_ce;
            uint64_t sent_time = acked.back().sent_time;
            OnCongestionEvent(sent_time);
        }
        auto lost_packets = ns->DetectAndRemoveLostPackets(&rtt);
        if (!lost_packets.empty()) {
            OnPacketsLost(ns, lost_packets);
        }
        OnPacketsAcked(acked, ack_delay_us);
        if(PeerCompletedAddressValidation()){
            pto_count = 0;
        }
        SetLossDetectionTimer();
    }
    if(level == ssl_encryption_initial || level == ssl_encryption_handshake){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    } else if(!ns->pend_frames.empty() && congestion_window > bytes_in_flight + max_datagram_size) {
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    } else if(JobPending(packet_tx) == 0 && ns->should_ack) {
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 20);
    }
    return streamIds;
}

void QuicQos::HandleRetry() {
    bytes_in_flight = 0;
    pn_namespace* ns = GetNamespace(ssl_encryption_initial);
    ns->current_pn = 0;
    ns->time_of_last_ack_eliciting_packet = 0;

    for(auto& packet: ns->sent_packets){
        assert(!packet.frames.empty());
        for(auto frame: packet.frames){
            PushFrame(ns, frame);
        }
    }
    ns->sent_packets.clear();
}

void QuicQos::PushFrame(pn_namespace* ns, quic_frame *frame) {
    if(has_drain_all) {
        dumpFrame("<", 'X', frame);
        return;
    }
    dumpFrame("<", ns->name, frame);
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    ns->pend_frames.push_back(frame);
    if(congestion_window > bytes_in_flight + max_datagram_size){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    } else {
        LOGD(DQUIC, "skip send, congestion_window: %zd, bytes_in_flight: %zd\n",
             congestion_window, bytes_in_flight);
    }
}

void QuicQos::FrontFrame(pn_namespace* ns, quic_frame *frame) {
    dumpFrame("<", ns->name, frame);
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    ns->pend_frames.push_front(frame);
    if(congestion_window > bytes_in_flight + max_datagram_size){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    } else {
        LOGD(DQUIC, "skip send, congestion_window: %zd, bytes_in_flight: %zd\n",
             congestion_window, bytes_in_flight);
    }
}

void QuicQos::PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame) {
    return PushFrame(GetNamespace(level), frame);
}

void QuicQos::DrainAll(){
    has_drain_all = true;
    for(auto& pn : pns) {
        delete pn;
        pn = nullptr;
    }
    loss_timer.reset(nullptr);
    packet_tx.reset(nullptr);
}

size_t QuicQos::PendingSize(OSSL_ENCRYPTION_LEVEL level) {
    pn_namespace* ns = this->GetNamespace(level);
    size_t len = 0;
    for(auto& i : ns->pend_frames) {
        len += frame_size(i);
    }
    for(auto& i : ns->sent_packets) {
        len += i.meta.sent_bytes;
    }
    return len;
}

size_t QuicQos::mem_usage() {
    size_t usage = sizeof(pns)/sizeof(pns[1]) * sizeof(pn_namespace);
    for(const auto pn : pns){
        usage += pn->tracked_receipt_pns.items.size() * 2 * sizeof(uint64_t);
        usage += pn->sent_packets.size() * sizeof(quic_packet_pn);
        for(const auto& packet: pn->sent_packets) {
            for(const auto& frame : packet.frames) {
                usage += frame_size(frame);
            }
        }
        usage += pn->pend_frames.size() * sizeof(quic_frame*);
        for(const auto& frame: pn->pend_frames) {
            usage += frame_size(frame);
        }
    }
    return usage;
}
