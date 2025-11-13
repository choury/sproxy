#ifndef RGUEST3_H_
#define RGUEST3_H_

#include "guest3.h"

class Rguest3: public Guest3{
    Destination dest;
    std::string name;
    uint32_t starttime;
    bool respawned = false;
    static size_t next_retry;
public:
    Rguest3(const Destination& dest, const std::string& name);
    virtual void deleteLater(uint32_t errcode) override;
};

#endif // RGUEST3_H_
