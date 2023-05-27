#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "common/base.h"
#include "prot/http/http_def.h"
#include "misc/index.h"

class Requester;

class Responser:public Server{
public:
    //src is usefull to status
    virtual void request(std::shared_ptr<HttpReq> req, Requester* src) = 0;
};

extern bimap<std::string, Responser*> responsers;
void distribute(std::shared_ptr<HttpReq> req, Requester* src);
#endif
