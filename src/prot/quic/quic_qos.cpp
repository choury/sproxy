//
// Created by choury on 2021/8/22.
//

#include "quic_qos.h"
#include "quic_cubic.h"
#include "quic_bbr.h"
#include "misc/config.h"

#include <assert.h>
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
    RttInit(&rtt);
}


QuicQos::~QuicQos() {
    DrainAll();
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
        auto lost_packets = ns->DetectAndRemoveLostPackets(&rtt);
        LOGD(DQUIC, "loss timer expired for [%c], loss_time: %.2fms, lost: %zd\n",
             ns->name, (now - ns->time_of_last_ack_eliciting_packet) / 1000.0, lost_packets.size());
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

void QuicQos::sendPacket(bool force) {
    uint64_t now = getutime();
    has_packet_been_congested = false;
    for(auto &p: pns){
        if(!p->hasKey){
            continue;
        }
        p->PendAck();
        if(p->pend_frames.empty()) {
            continue;
        }
        int window = sendWindow();
        LOGD(DQUIC, "%ssendPacket, pto_count: %zu, sendWindow: %d, windowLeft: %d, bytes_in_flight: %zd\n",
            force?"*":"", pto_count, window, (int)windowLeft(), bytes_in_flight);
        if(force && window < (int)max_datagram_size) {
            window = max_datagram_size;
        }
        size_t packets;
        if(pto_count > 0) {
            //如果在丢包探测阶段，只发送一个包
            bytes_in_flight += p->sendPacket(1200, delivered_bytes, packets);
            packets_sent += packets;
            last_sent_time = now;
            return;
        }
        if(window >= (int)max_datagram_size) {
            bytes_in_flight += p->sendPacket(window, delivered_bytes, packets);
            if(packets > 0) {
                packets_sent += packets;
                last_sent_time = now;
            }
        }
        if(!p->pend_frames.empty()){
            has_packet_been_congested = true;
            break;
        }
    }
    if(has_packet_been_congested && windowLeft() >= (int)max_datagram_size) {
        //sendwidonw或者udp的buffer满了，等一会重试
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 10);
    }
    if(bytes_in_flight > 0){
        SetLossDetectionTimer();
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
        auto acked = ns->DetectAndRemoveAckedPackets(&frame->ack, &rtt, his_max_ack_delay * 1000);
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
        OnPacketsAcked(acked);
        if(PeerCompletedAddressValidation()){
            pto_count = 0;
        }
        SetLossDetectionTimer();
    }
    int delay = -1;
    if(level == ssl_encryption_initial || level == ssl_encryption_handshake){
        delay = 0;
    } else if(ns->should_ack) {
        delay = 20;
    }
    if(delay >= 0 && JobPending(packet_tx) > (uint32_t)delay) {
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, (uint32_t)delay);
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

void QuicQos::maySend() {
    if(sendWindow() < (int)max_datagram_size) {
        LOGD(DQUIC, "skip send, sendwindow: %zd, winowleft: %zd, bytes_in_flight: %zd\n",
             sendWindow(), windowLeft(), bytes_in_flight);
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 10);
        return;
    }
    auto ns = GetNamespace(ssl_encryption_application);
    if(!ns->hasKey || ns->pend_frames.size() >= 100 || getutime() - last_sent_time >= 10000){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    }else if(JobPending(packet_tx) > 10) {
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 10);
    }
}

void QuicQos::PushFrame(pn_namespace* ns, quic_frame *frame) {
    if(has_drain_all) {
        dumpFrame("<", 'X', frame);
        return;
    }
    dumpFrame("<", ns->name, frame);
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    ns->pend_frames.push_back(frame);
    maySend();
}

void QuicQos::FrontFrame(pn_namespace* ns, quic_frame *frame) {
    dumpFrame("*<", ns->name, frame);
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    ns->pend_frames.push_front(frame);
    maySend();
}

void QuicQos::PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame) {
    return PushFrame(GetNamespace(level), frame);
}

void QuicQos::Migrated() {
    RttInit(&rtt);
    pto_count = 0;
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

std::unique_ptr<QuicQos> createQos(
    bool isServer,
    const QuicQos::send_func& sent,
    std::function<void(pn_namespace*, quic_frame*)> resendFrames
) {
    if(opt.quic_cc_algorithm && strcmp(opt.quic_cc_algorithm, "bbr") == 0){
        return std::make_unique<QuicBBR>(isServer, sent, resendFrames);
    }
    return std::make_unique<QuicCubic>(isServer, sent, resendFrames);
}
