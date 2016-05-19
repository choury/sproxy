#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "peer.h"
#include "parse.h"

class Responser:public Peer{
protected:
    virtual void closeHE(uint32_t events) override;
public:
    Ptr guest_ptr;
    virtual Ptr request(HttpReqHeader &req) = 0;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
};

Ptr distribute(HttpReqHeader& req, Ptr responser_ptr);

#endif
