//
// Created by choury on 4/6/24.
//

#include "rproxy3.h"

Rproxy3::Rproxy3(std::shared_ptr<RWer> rwer, std::string name):Proxy3(rwer), name(name) {
}

void Rproxy3::init() {
    if(rproxys.count(name)) {
        return deleteLater(RPROXY_DUP);
    }
    rproxys[name] = this;
    Http3Base::Init();
}

void Rproxy3::deleteLater(uint32_t errcode) {
    rproxys.erase(name);
    Proxy3::deleteLater(errcode);
}
