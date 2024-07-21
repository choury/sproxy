//
// Created by choury on 4/6/24.
//

#include "rproxy.h"
#include "req/requester.h"
#include "res/proxy2.h"
#include "misc/strategy.h"
#include "misc/util.h"

Responser* rproxy = nullptr;

Responser* RproxyCreate(std::shared_ptr<RWer> rwer) {
    auto proxy2 = new Proxy2(rwer);
    proxy2->init(nullptr);
    if(isalive(rproxy)) {
        rproxy->deleteLater(PEER_LOST_ERR);
    }
    rproxy = proxy2;
    return rproxy;
}

void RproxyRequest(std::shared_ptr<HttpReq> req, Requester* src) {
    uint64_t id = req->header->request_id;
    if(!checkauth(src->getid(), req->header->get("Authorization"))){
        req->response(std::make_shared<HttpRes>(HttpResHeader::create(S401, sizeof(S401), id), ""));
        return;
    }
    if(!isalive(rproxy)) {
        rproxy = nullptr;
    }
    auto header = req->header;
    std::string path = header->path;
    memset(&header->Dest, 0, sizeof(header->Dest));
    if(spliturl(path.c_str() + 8, &header->Dest, header->path)) {
        req->response(std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id), ""));
        return;
    }
    header->postparse();
    LOG("rproxy: %s -> %s\n", path.c_str(), header->geturl().c_str());
    if(rproxy) {
        header->set(STRATEGY, "rproxy");
        rproxy->request(req, src);
    } else {
        distribute(req, src);
    }
}
