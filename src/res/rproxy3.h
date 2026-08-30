//
// Created by choury on 4/6/24.
//

#ifndef SPROXY_RPROXY3_H
#define SPROXY_RPROXY3_H

#include "proxy3.h"

class Rproxy3: public Proxy3 {
    std::string name;
protected:
    virtual void setIdle(uint32_t) override {};
    virtual void PushProc(uint64_t pushid, std::shared_ptr<HttpReqHeader> req) override;
public:
    using Proxy3::Proxy3;
    virtual void deleteLater(uint32_t errcode) override;

    void init();
};

#endif //SPROXY_RPROXY3_H