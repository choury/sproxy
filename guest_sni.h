#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"


class Guest_sni: public Guest{
    virtual void defaultHE(uint32_t events)override;
};

#endif