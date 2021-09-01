//
// Created by 周威 on 2021/8/22.
//

#include "quic_pn.h"
#include <inttypes.h>
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
    if(items.empty()){
        items.emplace_back(pn, pn);
        latest_time = getutime();
        return;
    }
    if(pn == items.back().second + 1){
        items.back().second++;
        latest_time = getutime();
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
        if(pn < i->first){
            return;
        }
        i->first = pn;
        return;
    }
}

void pn_namespace::PendAck() {
    if(!should_ack || latest_ack >= pns.items.back().second){
        return;
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
    if(ack->ack.range_count && pendq.empty()){
        //append ping if only ack
        quic_frame* ping = new quic_frame;
        ping->type = QUIC_FRAME_PING;
        pendq.push_back(ping);
    }
    latest_ack = ack->ack.acknowledged;

    LOGD(DQUIC, "< [%c] ack frame: %" PRIu64"[%" PRIu64"]\n",
         name, ack->ack.acknowledged, (ack->ack.delay << 3)/1000);
    pendq.push_front(ack);
}

void pn_namespace::HandleAck(const quic_ack *frame) {
    if(frame->acknowledged > largest_ack){
        largest_ack = frame->acknowledged;
    }
    Chop p(frame);
    for(auto i = sendq.begin(); i != sendq.end();){
        if(p.Has(i->pn)){
            if(i->frame->type == QUIC_FRAME_ACK || i->frame->type == QUIC_FRAME_ACK_ECN){
                LOGD(DQUIC, "clean pn before: %" PRIu64"\n", i->frame->ack.acknowledged);
                pns.Erase(i->frame->ack.acknowledged);
            }
            frame_release(i->frame);
            delete i->frame;
            i = sendq.erase(i);
        }else{
            i++;
        }
    }
}

pn_namespace::~pn_namespace() {
    for(auto i : pendq){
        frame_release(i);
        delete i;
    }
    for(auto i : sendq){
        frame_release(i.frame);
        delete i.frame;
    }
    pendq.clear();
    sendq.clear();
}