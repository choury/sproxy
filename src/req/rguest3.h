#ifndef RGUEST3_H_
#define RGUEST3_H_

#include "guest3.h"

class Rguest3: public Guest3{
    std::string name;
    void connected();
public:
    Rguest3(const Destination& dest, const std::string& name);
    virtual void deleteLater(uint32_t errcode) override;
};

#endif // RGUEST3_H_