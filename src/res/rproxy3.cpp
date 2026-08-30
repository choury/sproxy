//
// Created by choury on 4/6/24.
//

#include "rproxy3.h"

void Rproxy3::init() {
    return Proxy3::init(true, nullptr, nullptr);
}

void Rproxy3::PushProc(uint64_t pushid, std::shared_ptr<HttpReqHeader> req) {
    LOG("Push frame [%" PRIu64 "]: %s\n", pushid, req->geturl().c_str());
    if(memcmp(req->path, "/rproxy/", 8) != 0) {
        return deleteLater(PROTOCOL_ERR);
    }
    std::string pname = req->path + 8;
    if(pname.empty()) {
        return deleteLater(PROTOCOL_ERR);
    }
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

void Rproxy3::deleteLater(uint32_t errcode) {
    if(rproxys.count(name) && rproxys[name] == this) {
        rproxys.erase(name);
    }
    Proxy3::deleteLater(errcode);
}
