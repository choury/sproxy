//
// Created by choury on 4/6/24.
//

#ifndef SPROXY_RPROXY_H
#define SPROXY_RPROXY_H

#include "proxy2.h"

class Rproxy2: public Proxy2 {
    std::string name;
    virtual void setIdle(uint32_t) override {}
    virtual void PushProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) override;
public:
    using Proxy2::Proxy2;
    virtual void deleteLater(uint32_t errcode) override;

    void init();
};

#endif //SPROXY_RPROXY_H
