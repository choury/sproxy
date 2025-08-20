//
// Created by choury on 4/6/24.
//

#include "rproxy2.h"

Rproxy2::Rproxy2(std::shared_ptr<RWer> rwer, std::string name):Proxy2(rwer), name(name) {
}

void Rproxy2::init() {
    if(!name.empty()) {
        if(rproxys.count(name)) {
            return deleteLater(RPROXY_DUP);
        }
        if(name == "local") {
            return deleteLater(RPROXY_DUP);
        }
        rproxys[name] = this;
    }
    return Proxy2::init(true, nullptr, nullptr);
}


void Rproxy2::PushProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) {
    LOG("Push frame [%d]: %s\n", (int)id, req->geturl().c_str());
    if(memcmp(req->path, "/rproxy/", 8) != 0) {
        return deleteLater(PROTOCOL_ERR);
    }
    std::string pname = req->path + 8;
    if(name == pname) {
        return;
    } else if(!name.empty()) {
        return deleteLater(RPROXY_DUP);
    }
    name = pname;
    if(rproxys.count(name)) {
        return deleteLater(RPROXY_DUP);
    }
    if(name == "local") {
        return deleteLater(RPROXY_DUP);
    }
    rproxys[name] = this;
}

void Rproxy2::deleteLater(uint32_t errcode) {
    if(rproxys.count(name) && rproxys[name] == this) {
        rproxys.erase(name);
    }
    Proxy2::deleteLater(errcode);
}
