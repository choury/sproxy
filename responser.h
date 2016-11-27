#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "peer.h"
#include "parse.h"

class Requester;

class Responser:public Peer{
protected:
    virtual void closeHE(uint32_t events) override;
public:
    virtual void ResetRequester(Requester *r, uint32_t);
    virtual uint32_t request(HttpReqHeader&& req) = 0;
};

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr, uint32_t id);

#endif
