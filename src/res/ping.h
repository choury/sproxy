#ifndef PING_H__
#define PING_H__

#include "responser.h"


class Ping: public Responser{
    std::shared_ptr<HttpReq>    req;
    std::shared_ptr<HttpRes>    res;
    uint16_t    id = 0;
    uint16_t    seq = 1;
    sa_family_t family = 0;
    bool        israw  = false;
    void Recv(Buffer&& bb);
public:
    Ping(const char *host, uint16_t id);
    explicit Ping(std::shared_ptr<HttpReqHeader> req);
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
};
#endif
