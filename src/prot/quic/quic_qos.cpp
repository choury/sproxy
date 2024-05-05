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


class Chop{
    void refactor();
public:
    std::list<std::pair<uint64_t, uint64_t>> items;
    uint64_t latest_time = 0;

    Chop() = default;
    explicit Chop(const quic_ack* frame);
    void Add(uint64_t pn);
    bool Has(uint64_t pn);
    uint64_t Max();
    // delete number before pN;
    void EraseBefore(uint64_t pn);
    void dump();
};


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


class pn_namespace{
    typedef std::function<std::list<quic_packet_pn>(uint64_t pn, uint64_t ack,
                                                    std::list<quic_frame*>& pend_frames, size_t window)> send_func;
    send_func sent;
    uint64_t current_pn     = 0;
    bool     hasKey = false;
    char     name;
    Chop     tracked_receipt_pns;
    bool     should_ack  = false;
    uint64_t largest_acked_packet = UINT64_MAX;   // largest acked packet from peer
    uint64_t ack_delay_exponent = 3;
    uint64_t time_of_last_ack_eliciting_packet = 0;
    uint64_t ecn_ce_counters = 0;
    uint64_t loss_time = UINT64_MAX;
    std::list <quic_frame*>    pend_frames;
    std::list <quic_packet_pn> sent_packets;

    int sendPacket(size_t window);
    void PendAck();
    std::list<quic_packet_meta> DetectAndRemoveAckedPackets(const quic_ack* ack, Rtt* rtt, uint64_t max_delay_us);
    std::list<quic_packet_pn> DetectAndRemoveLostPackets(Rtt* rtt);
    void clear();
public:
    pn_namespace(char name, send_func sent);
    ~pn_namespace();

    friend class QuicQos;
};


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

/*
int pn_namespace::sendOnePacket(size_t window){
    uint64_t now = getutime();
    bool ack_eliciting = false;
    bool in_flight = false;

    size_t envelopLen = sent(current_pn, largest_acked_packet+1, nullptr,
                             std::min((size_t)max_datagram_size, window), {});

    std::set<uint64_t> streams;
    char buff[max_datagram_size];
    char* pos = buff;
    auto i = pend_frames.begin();
    for(; i != pend_frames.end(); i++) {
        ssize_t left = std::min((size_t)max_datagram_size, window) + buff - pos - envelopLen;
        if(left < (int)pack_frame_len(*i)){
            uint64_t type = (*i)->type;
            if(type == QUIC_FRAME_CRYPTO && left >= 20){
                // [n, m) -> [n, n + left - 20) + [n + left - 20, m)
                quic_frame* frame = new quic_frame{type, {}};
                frame->crypto.offset = (*i)->crypto.offset + left - 20;
                frame->crypto.length = (*i)->crypto.length - left + 20;
                frame->crypto.buffer.data = (*i)->crypto.buffer.data + left - 20;
                frame->crypto.buffer.ref = (*i)->crypto.buffer.ref;
                (*frame->crypto.buffer.ref)++;
                pend_frames.insert(std::next(i), frame);
                (*i)->crypto.length = left - 20;
            }else if((type >= QUIC_FRAME_STREAM_START_ID && type <= QUIC_FRAME_STREAM_END_ID) && left >= 30){
                streams.emplace((*i)->stream.id);
                // [n, m) -> [n, n + left - 30) + [n + left - 30, m)
                quic_frame* frame = new quic_frame{type | QUIC_FRAME_STREAM_OFF_F, {}};
                frame->stream.id = (*i)->stream.id;
                frame->stream.offset = (*i)->stream.offset + left - 30;
                frame->stream.length = (*i)->stream.length - left + 30;
                frame->stream.buffer.data = (*i)->stream.buffer.data + left - 30;
                frame->stream.buffer.ref = (*i)->stream.buffer.ref;
                (*frame->stream.buffer.ref)++;
                pend_frames.insert(std::next(i), frame);
                (*i)->stream.length = left - 30;
                (*i)->type &= ~QUIC_FRAME_STREAM_FIN_F;
            }else{
                break;
            }
        }
        pos = (char*)pack_frame(pos, *i);
        if(pos == nullptr){
            return -QUIC_INTERNAL_ERROR;
        }
        ack_eliciting = ack_eliciting || is_ack_eliciting(*i);
        in_flight = in_flight || ack_eliciting || (*i)->type == QUIC_FRAME_PADDING;
    }
    if(i == pend_frames.begin()){
        //there is no frame sent
        return 0;
    }
    int ret = sent(current_pn, largest_acked_packet+1, buff, pos - buff, streams);
    if(ret < 0){
        return ret;
    }
    decltype(pend_frames) sent_frames;
    sent_frames.splice(sent_frames.begin(), pend_frames, pend_frames.begin(), i);
    sent_packets.push_back(quic_packet_pn{
            {current_pn, ack_eliciting, in_flight, (size_t)ret, now},
            std::move(sent_frames)});

    assert(!sent_packets.back().frames.empty());
    current_pn++;
    if(in_flight){
        if(ack_eliciting){
            time_of_last_ack_eliciting_packet = now;
        }
        return ret;
    }
    return 0;
}

 */

int pn_namespace::sendPacket(size_t window) {
    auto packets = sent(current_pn, largest_acked_packet + 1, pend_frames, window);
    if(packets.empty()) {
        return 0;
    }
    current_pn = packets.back().meta.pn + 1;

    size_t flight_size = 0;
    for(const auto& packet: packets) {
        if(packet.meta.in_flight) {
            flight_size += packet.meta.sent_bytes;
        }
        if(packet.meta.ack_eliciting) {
            time_of_last_ack_eliciting_packet = packet.meta.sent_time;
        }
    }
    sent_packets.splice(sent_packets.end(), packets);
    return flight_size;
}

std::list<quic_packet_meta> pn_namespace::DetectAndRemoveAckedPackets(
        const quic_ack *ack, Rtt* rtt, uint64_t max_delay_us)
{
    if(largest_acked_packet == UINT64_MAX || largest_acked_packet < ack->acknowledged){
        largest_acked_packet = ack->acknowledged;
    }
    std::list<quic_packet_meta> newly_acked_packets;
    uint64_t now = getutime();
    Chop p(ack);
    uint64_t ack_delay = ack->delay << ack_delay_exponent;
    if(max_delay_us && (ack_delay > max_delay_us)){
        ack_delay = max_delay_us;
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
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
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
            bytes_in_flight += p->sendPacket(max_datagram_size);
            return;
        }else if(!p->pend_frames.empty() && congestion_window > bytes_in_flight + max_datagram_size) {
            bytes_in_flight += p->sendPacket(congestion_window - bytes_in_flight);
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
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
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
    LOGD(DQUIC, "cut congestion_window to %zd\n", bytes_in_flight);
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

void QuicQos::OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets) {
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
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();} , 0);
    }
}

void QuicQos::handleFrame(OSSL_ENCRYPTION_LEVEL level, uint64_t number, const quic_frame *frame) {
    pn_namespace* ns = this->GetNamespace(level);
    dumpFrame(">", ns->name, frame);
    if(!ns->hasKey){
        //key has dropped before handle it.
        return;
    }
    ns->tracked_receipt_pns.Add(number);
    if(level == ssl_encryption_initial || level == ssl_encryption_handshake){
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
    }else if(JobPending(packet_tx) == 0 && congestion_window > bytes_in_flight + max_datagram_size) {
        packet_tx  = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 20);
    }
    if(is_ack_eliciting(frame)){
        ns->should_ack = true;
    }
    //FIXME:
    // When a server is blocked by anti-amplification limits, receiving a datagram unblocks it,
    // even if none of the packets in the datagram are successfully processed.
    // In such a case, the PTO timer will need to be rearmed.

    if(frame->type == QUIC_FRAME_ACK || frame->type == QUIC_FRAME_ACK_ECN){
        last_receipt_ack_time = getutime();
        auto acked = ns->DetectAndRemoveAckedPackets(&frame->ack, &rtt, his_max_ack_delay * 1000);
        if(acked.empty()){
            return;
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
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();} , 0);
    }
}

void QuicQos::FrontFrame(pn_namespace* ns, quic_frame *frame) {
    dumpFrame("<", ns->name, frame);
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    ns->pend_frames.push_front(frame);
    if(congestion_window > bytes_in_flight + max_datagram_size){
        packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();} , 0);
    }
}

void QuicQos::PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame) {
    return PushFrame(GetNamespace(level), frame);
}

void QuicQos::SendNow() {
    packet_tx = UpdateJob(std::move(packet_tx), [this]{sendPacket();}, 0);
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
