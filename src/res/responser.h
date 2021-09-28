#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "common/base.h"
#include "prot/http/http_def.h"

class Requester;

class Responser:public Server{
public:
    virtual void request(std::shared_ptr<HttpReq> req, Requester* src) = 0;
};

void distribute(std::shared_ptr<HttpReq> req, Requester* src);
#endif
