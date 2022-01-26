//
// Created by 周威 on 2021/8/22.
//

#include "quic_pn.h"
#include <inttypes.h>
#include <assert.h>
#include <misc/util.h>

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

void Chop::PushPn(uint64_t pn) {
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
    items.push_front(std::make_pair(pn, pn));
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

void Chop::Erase(uint64_t pn) {
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

uint64_t pn_namespace::PendAck() {
    uint64_t now = getutime();
    if(!should_ack || latest_ack >= pns.items.back().second){
        return now;
    }
    should_ack = false;
    quic_frame *ack = new quic_frame;
    memset(ack, 0, sizeof(quic_frame));
    ack->type = QUIC_FRAME_ACK;
    ack->ack.acknowledged = pns.items.back().second;
    ack->ack.delay = (getutime() - pns.latest_time) >> 3;
    ack->ack.first_range = pns.items.back().second - pns.items.back().first;
    ack->ack.range_count = pns.items.size() - 1;
    ack->ack.ranges = new quic_ack_range[ack->ack.range_count];
    int index = 0;
    for(auto i = pns.items.rbegin(); i != pns.items.rend();){
        auto j = i++;
        if(i == pns.items.rend()){
            break;
        }
        ack->ack.ranges[index].gap = j->first - i->second - 2;
        ack->ack.ranges[index].length = i->second - i->first;
        index++;
    }
    if(ack->ack.range_count && pend_frames.empty()){
        //append ping if only ack
        quic_frame* ping = new quic_frame;
        ping->type = QUIC_FRAME_PING;
        pend_frames.push_back(ping);
    }
    latest_ack = ack->ack.acknowledged;

    LOGD(DQUIC, "< [%c] ack frame %" PRIu64": %.2fms\n",
         name, ack->ack.acknowledged, (ack->ack.delay << 3)/1000.0);
    pend_frames.push_front(ack);
    return now;
}

void pn_namespace::PnAcknowledged(quic_packet_pn &pn) {
    for(auto frame: pn.frames) {
        if (frame->type == QUIC_FRAME_ACK || frame->type == QUIC_FRAME_ACK_ECN) {
            LOGD(DQUIC, "clean pN before: %" PRIu64"\n", frame->ack.acknowledged);
            pns.Erase(frame->ack.acknowledged);
        }
        frame_release(frame);
    }
}

bool pn_namespace::HandleAck(const quic_ack *frame, Rtt* rtt,
                             uint64_t max_delay_us, std::function<void(quic_frame*)> resendFrame)
{
    uint64_t now = getutime();
    Chop p(frame);
    uint64_t ack_delay = frame->delay << ack_delay_exponent;
    if(max_delay_us && (ack_delay > max_delay_us)){
        ack_delay = max_delay_us;
    }
    largest_acked_packet = std::max(frame->acknowledged, largest_acked_packet);
    bool newly_ack = false;
    bool ack_elicited = false;
    uint64_t send_time_of_largest_acked = 0;
    for(auto i = sent_packets.begin(); i != sent_packets.end();){
        if(frame->acknowledged == i->pn){
            send_time_of_largest_acked = i->time_sent;
        }
        if(p.Has(i->pn)){
            newly_ack = true;
            if(i->ack_eliciting){
                ack_elicited = true;
            }
            PnAcknowledged(*i);
            i = sent_packets.erase(i);
        } else {
            i++;
        }
    }
    if(!newly_ack){
        return false;
    }
    if(ack_elicited && send_time_of_largest_acked) {
        rtt->latest_rtt = now - send_time_of_largest_acked;
        if (rtt->latest_rtt < rtt->min_rtt) {
            rtt->min_rtt = rtt->latest_rtt;
        }
        if (rtt->smoothed_rtt == 0) {
            rtt->min_rtt = rtt->latest_rtt;
            rtt->smoothed_rtt = rtt->latest_rtt;
            rtt->rttvar = rtt->latest_rtt / 2;
        }else {
            if (rtt->latest_rtt >= rtt->min_rtt + ack_delay) {
                rtt->latest_rtt = rtt->latest_rtt - ack_delay;
            }
            rtt->smoothed_rtt = (7 * rtt->smoothed_rtt + rtt->latest_rtt) / 8;
            uint64_t rttvar_sample = rtt->smoothed_rtt > rtt->latest_rtt ?
                                     rtt->smoothed_rtt - rtt->latest_rtt : rtt->latest_rtt - rtt->smoothed_rtt;
            rtt->rttvar = (3 * rtt->rttvar + rttvar_sample) / 4;
        }
        LOGD(DQUIC, "smoothed_rtt: %.2fms, rttvar: %.2fms, latest_rtt: %.2fms\n",
             rtt->smoothed_rtt/1000.0, rtt->rttvar/1000.0, rtt->latest_rtt/1000.0);
    }
    DetectLostPackets(rtt, resendFrame);
    return true;
}

void pn_namespace::DetectLostPackets(Rtt* rtt, std::function<void(quic_frame*)> resendFrame) {
    loss_time = UINT64_MAX;
    assert(rtt->latest_rtt);
    uint64_t now = getutime();
    uint64_t timeThreshold = std::max(9 * std::max(rtt->smoothed_rtt, rtt->latest_rtt) / 8, (uint64_t)1000);
    for(auto i = sent_packets.begin(); i != sent_packets.end();){
        if(i->pn > largest_acked_packet){
            i++;
            continue;
        }
        if(largest_acked_packet - i->pn >= 3 || now - i->time_sent >= timeThreshold){
            LOGD(DQUIC, "[%c] mark lost packet: [%" PRIu64"]\n", name, i->pn);
            for(auto frame: i->frames){
                resendFrame(frame);
            }
            i = sent_packets.erase(i);
            continue;
        }else if(i->time_sent + timeThreshold  < loss_time){
            loss_time = i->time_sent + timeThreshold;
        }
        i++;
    }
}

void pn_namespace::clear() {
    for(auto i : pend_frames){
        frame_release(i);
    }
    for(const auto& i : sent_packets){
        for(auto frame: i.frames) {
            frame_release(frame);
        }
    }
    for(const auto& frame: lost_frames){
        frame_release(frame);
    }
    pend_frames.clear();
    lost_frames.clear();
    sent_packets.clear();
    loss_time = UINT64_MAX;
    time_of_last_ack_eliciting_packet = 0;
}

pn_namespace::~pn_namespace() {
    clear();
}
