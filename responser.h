#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "peer.h"
#include "parse.h"

class Responser:public Peer{
protected:
    virtual void closeHE(uint32_t events) override;
    virtual void request(HttpReqHeader &req) = 0;
};

Responser* distribute(HttpReqHeader& req, Responser* responser_ptr);

#endif
