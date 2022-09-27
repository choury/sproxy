#ifndef PING_H__
#define PING_H__

#include "responser.h"


class Ping: public Responser{
    std::shared_ptr<HttpReq>    req;
    std::shared_ptr<HttpRes>    res;
    uint16_t    id = 0;
    uint16_t    seq = 1;
    sa_family_t family = 0;
#define PING_IS_RAW_SOCK  1
#define PING_IS_CLOSED_F  2
    uint32_t    flags  = 0;
    void Recv(Buffer&& bb);
public:
    Ping(const char *host, uint16_t id);
    explicit Ping(std::shared_ptr<HttpReqHeader> req);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};
#endif
