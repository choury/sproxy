#ifndef RGUEST2_H_
#define RGUEST2_H_

#include "guest2.h"


class Rguest2: public Guest2{
    Destination dest;
    std::string name;
    uint32_t starttime;
    bool respawned = false;
    static size_t next_retry;
    virtual size_t InitProc(Buffer& bb) override;
public:
    Rguest2(const Destination& dest, const std::string& name);
    void ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) override;
    virtual void deleteLater(uint32_t errcode) override;
};

#endif // RGUEST2_H_
