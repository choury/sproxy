//
// Created by choury on 4/6/24.
//

#ifndef SPROXY_RPROXY3_H
#define SPROXY_RPROXY3_H

#include "proxy3.h"

class Rproxy3: public Proxy3 {
    std::string name;
protected:
    Destination getPeer() {
        return rwer->getSrc();
    }
    virtual void setIdle(uint32_t) override {};
public:
    explicit Rproxy3(std::shared_ptr<RWer> rwer, std::string name);
    virtual void deleteLater(uint32_t errcode) override;

    void init();
};

#endif //SPROXY_RPROXY3_H