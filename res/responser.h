#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "base.h"
#include "prot/http_pack.h"

class Requester;

class Responser:public Peer{
public:
    virtual void* request(HttpReqHeader* req) = 0;
    virtual void* request(HttpReq&& req);
};

Responser* distribute(HttpReqHeader* req, Responser* responser_ptr);

#endif
