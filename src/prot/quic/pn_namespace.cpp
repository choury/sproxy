//
// Created by choury on 24-6-6.
//

#include "pn_namespace.h"
#include "misc/buffer.h"

#include <inttypes.h>


Chop::Chop(const quic_ack *frame) {
    items.emplace_front(frame->acknowledged - frame->first_range, frame->acknowledged);
    for(size_t i = 0; i < frame->range_count; i++){
        auto pos = items.begin();
        uint64_t second = pos->first - frame->ranges[i].gap - 2;
        uint64_t first  = second - frame->ranges[i].length;
        items.insert(pos, std::make_pair(first, second));
    }
}

void Chop::refactor() {
    for(auto i = items.begin();;){
        auto j = i++;
        if(i == items.end()){
            return;
        }
        if(j->second >= i->first-1){
            j->second = i->second;
            items.erase(i);
            i = j;
        }
    }
}

void Chop::Add(uint64_t pn) {
    auto now = getutime();
    if(items.empty()){
        latest_time = now;
        items.emplace_back(pn, pn);
        return;
    }
    if(pn == items.back().second + 1){
        latest_time = now;
        items.back().second++;
        return;
    }
    if(pn > items.back().second){
        latest_time = now;
        items.emplace_back(pn, pn);
        return;
    }
    for(auto i = items.rbegin(); i != items.rend(); i++){
        if(pn == i->second + 1){
            i->second ++;
            return refactor();
        }
        if(pn == i->first -1){
            i->first --;
            return refactor();
        }
        if(pn <= i->second && pn >= i->first){
            //dup pkg
            return;
        }
        if(pn > i->second){
            items.insert(i.base(), std::make_pair(pn, pn));
            return;
        }
    }
    items.emplace_front(pn, pn);
}


bool Chop::Has(uint64_t pn) {
    for(auto& item : items){
        if(pn < item.first){
            return false;
        }
        if(pn <= item.second){
            return true;
        }
    }
    return false;
}

uint64_t Chop::Max() {
    return items.back().second;
}


void Chop::EraseBefore(uint64_t pn) {
    for(auto i = items.begin(); i != items.end();){
        if(pn >= i->second){
            i = items.erase(i);
            continue;
        }
        if(pn <= i->first){
            return;
        }
        i->first = pn;
        return;
    }
}

void Chop::dump() {
    for(auto& i: items){
        LOGD(DQUIC, "%d - %d\n", (int)i.first, (int)i.second);
    }
}

pn_namespace::pn_namespace(char name, send_func sent):
        sent(std::move(sent)), name(name) {
}

void pn_namespace::PendAck() {
    if(!should_ack){
        return;
    }
    assert(!tracked_receipt_pns.items.empty());
    should_ack = false;
    quic_frame *ack = new quic_frame;
    memset(ack, 0, sizeof(quic_frame));
    ack->type = QUIC_FRAME_ACK;
    ack->ack.acknowledged = tracked_receipt_pns.items.back().second;
    ack->ack.delay = (getutime() - tracked_receipt_pns.latest_time) >> 3;
    ack->ack.first_range = tracked_receipt_pns.items.back().second - tracked_receipt_pns.items.back().first;
    ack->ack.range_count = tracked_receipt_pns.items.size() - 1;
    ack->ack.ranges = new quic_ack_range[ack->ack.range_count];
    int index = 0;
    for(auto i = tracked_receipt_pns.items.rbegin(); i != tracked_receipt_pns.items.rend();){
        auto j = i++;
        if(i == tracked_receipt_pns.items.rend()){
            break;
        }
        ack->ack.ranges[index].gap = j->first - i->second - 2;
        ack->ack.ranges[index].length = i->second - i->first;
        index++;
    }
    if(ack->ack.range_count && pend_frames.empty()){
        //append ping if only ack
        pend_frames.emplace_back(new quic_frame{QUIC_FRAME_PING, {}});
    }

    dumpFrame("<", name, ack);
    pend_frames.push_front(ack);
}

size_t pn_namespace::sendPacket(size_t window) {
    size_t packets_sent;
    return sendPacket(window, packets_sent);
}

size_t pn_namespace::sendPacket(size_t window, size_t& packets_sent) {
    auto packets = sent(current_pn, largest_acked_packet + 1, pend_frames, window);
    if(packets.empty()) {
        packets_sent = 0;
        return 0;
    }
    packets_sent = packets.size();  // 返回实际发送的包数
    current_pn = packets.back().meta.pn + 1;
    bool app_limited = pend_frames.empty();

    size_t flight_size = 0;
    for(auto& packet: packets) {
        if(packet.meta.in_flight) {
            flight_size += packet.meta.sent_bytes;
        }
        if(packet.meta.ack_eliciting) {
            time_of_last_ack_eliciting_packet = packet.meta.sent_time;
        }
        packet.meta.app_limited = app_limited;
    }
    sent_packets.splice(sent_packets.end(), packets);
    return flight_size;
}

std::list<quic_packet_meta> pn_namespace::DetectAndRemoveAckedPackets(
        const quic_ack *ack, Rtt* rtt, uint64_t& ack_delay_us, uint64_t max_delay_us)
{
    if(largest_acked_packet == UINT64_MAX || largest_acked_packet < ack->acknowledged){
        largest_acked_packet = ack->acknowledged;
    }
    std::list<quic_packet_meta> newly_acked_packets;
    uint64_t now = getutime();
    Chop p(ack);
    ack_delay_us = ack->delay << ack_delay_exponent;
    if(max_delay_us && (ack_delay_us > max_delay_us)){
        ack_delay_us = max_delay_us;
    }
    bool ack_elicited = false;
    uint64_t latest_acked_pn = 0;
    for(auto i = sent_packets.begin(); i != sent_packets.end();){
        assert(!i->frames.empty());
        if(p.Has(i->meta.pn)){
            newly_acked_packets.emplace_back(i->meta);
            if(i->meta.ack_eliciting){
                ack_elicited = true;
            }
            for(auto frame: i->frames) {
                if (frame->type == QUIC_FRAME_ACK || frame->type == QUIC_FRAME_ACK_ECN) {
                    latest_acked_pn = frame->ack.acknowledged;
                }
                frame_release(frame);
            }
            i = sent_packets.erase(i);
        } else if(i->meta.pn > p.Max()){
            break;
        } else {
            i++;
        }
    }
    if(latest_acked_pn) {
        //对方已经确认了我们发送的ack,那么就意味着他们已经知晓我们发送的ack之前的pn信息
        //我们以后发送ack就可以不发送在这之前的pn信息了
        LOGD(DQUIC, "clean pn from tracking before: %" PRIu64"\n", latest_acked_pn);
        tracked_receipt_pns.EraseBefore(latest_acked_pn);
    }
    if(newly_acked_packets.empty()){
        return newly_acked_packets;
    }
    if(ack_elicited && newly_acked_packets.back().pn == ack->acknowledged){
        rtt->latest_rtt = now - newly_acked_packets.back().sent_time;
        if(rtt->first_rtt_sample == 0){
            rtt->min_rtt = rtt->latest_rtt;
            rtt->smoothed_rtt = rtt->latest_rtt;
            rtt->rttvar = rtt->latest_rtt / 2;
            rtt->first_rtt_sample = now;
        }else{
            if (rtt->latest_rtt < rtt->min_rtt) {
                rtt->min_rtt = rtt->latest_rtt;
            }
            if (rtt->latest_rtt >= rtt->min_rtt + ack_delay_us) {
                rtt->latest_rtt = rtt->latest_rtt - ack_delay_us;
            }
            rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + rtt->latest_rtt) / 8;
            uint64_t rttvar_sample = rtt->smoothed_rtt > rtt->latest_rtt ?
                                     rtt->smoothed_rtt - rtt->latest_rtt : rtt->latest_rtt - rtt->smoothed_rtt;
            rtt->rttvar = (3 * rtt->rttvar + rttvar_sample) / 4;
        }
        LOGD(DQUIC, "smoothed_rtt: %.2fms, rttvar: %.2fms, latest_rtt: %.2fms\n",
             rtt->smoothed_rtt/1000.0, rtt->rttvar/1000.0, rtt->latest_rtt/1000.0);
    }
    return newly_acked_packets;
}

std::list<quic_packet_pn> pn_namespace::DetectAndRemoveLostPackets(Rtt *rtt) {
    assert(largest_acked_packet != UINT64_MAX);
    loss_time = UINT64_MAX;
    std::list<quic_packet_pn> lost_packets;
    if(rtt->latest_rtt == 0){
        return lost_packets;
    }
    uint64_t now = getutime();
    uint64_t timeThreshold = std::max(9 * std::max(rtt->smoothed_rtt, rtt->latest_rtt) / 8, (uint64_t)1000);
    for(auto i = sent_packets.begin(); i != sent_packets.end();){
        assert(!i->frames.empty());
        if(i->meta.pn > largest_acked_packet){
            break;
        }
        if(largest_acked_packet - i->meta.pn >= kPacketThreshold || now - i->meta.sent_time >= timeThreshold){
            LOGD(DQUIC, "[%c] mark lost packet: [%" PRIu64"]\n", name, i->meta.pn);
            lost_packets.emplace_back(*i);
            i = sent_packets.erase(i);
            continue;
        }else if(i->meta.sent_time + timeThreshold < loss_time){
            loss_time = i->meta.sent_time + timeThreshold;
        }
        i++;
    }
    return lost_packets;
}

void pn_namespace::clear() {
    for(auto i : pend_frames){
        frame_release(i);
    }
    for(const auto& packet : sent_packets){
        assert(!packet.frames.empty());
        for(auto frame: packet.frames) {
            frame_release(frame);
        }
    }
    pend_frames.clear();
    sent_packets.clear();
    loss_time = UINT64_MAX;
    time_of_last_ack_eliciting_packet = 0;
    hasKey = false;
}

pn_namespace::~pn_namespace() {
    clear();
}


