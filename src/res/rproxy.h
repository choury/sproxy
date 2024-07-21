//
// Created by choury on 4/6/24.
//

#ifndef SPROXY_RPROXY_H
#define SPROXY_RPROXY_H

#include "responser.h"

Responser* RproxyCreate(std::shared_ptr<RWer> rwer);
void RproxyRequest(std::shared_ptr<HttpReq> req, Requester* src);

#endif //SPROXY_RPROXY_H
