#ifndef UHOST_H__
#define UHOST_H__

#include "responser.h"


class Uhost: public Responser{
    std::shared_ptr<HttpReq>    req;
    std::shared_ptr<HttpRes>    res;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    bool is_closing = false;
public:
    Uhost(const char *host, uint16_t id);
    explicit Uhost(std::shared_ptr<HttpReqHeader> req);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};
#endif
