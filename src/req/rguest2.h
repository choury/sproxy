#ifndef RGUEST2_H_
#define RGUEST2_H_

#include "guest2.h"


class Rguest2: public Guest2{
    std::string name;
    virtual size_t InitProc(Buffer& bb) override;
public:
    Rguest2(const Destination* dest, const std::string& name);
    virtual void deleteLater(uint32_t errcode) override;
};

#endif // RGUEST2_H_
