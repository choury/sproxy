//
// Created by 周威 on 2021/8/22.
//

#ifndef SPROXY_QUIC_PN_H
#define SPROXY_QUIC_PN_H

#include "quic_pack.h"

#include <stdint.h>
#include <list>

struct quic_frame_pn{
    uint64_t pn;
    struct quic_frame* frame;
};

class Chop{
    void refactor();
public:
    std::list<std::pair<uint64_t, uint64_t>> items;
    uint64_t latest_time = 0;

    Chop(){};
    Chop(const quic_ack* frame);
    void PushPn(uint64_t pn);
    bool Has(uint64_t pn);
    // delete number before pn;
    void Erase(uint64_t pn);
};

class pn_namespace{
public:
    Chop     pns;
    bool     should_ack  = false;
    uint64_t current     = 0;
    uint64_t largest_ack = 0;
    uint64_t latest_ack  = 0;
    uint64_t ack_delay_exponent = 3;
    char     name;
    std::list <quic_frame*>   pendq;
    std::list <quic_frame_pn> sendq;
    void PendAck();
    void HandleAck(const quic_ack* frame);
    ~pn_namespace();
};

#endif //SPROXY_QUIC_PN_H
