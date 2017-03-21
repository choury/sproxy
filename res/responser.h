#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "base.h"
#include "prot/http_pack.h"

class Requester;

class Responser:public Peer{
protected:
    virtual void closeHE(uint32_t events) override;
public:
    virtual void* request(HttpReqHeader&& req) = 0;
};

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr);

#endif
