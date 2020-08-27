#ifndef PING_H__
#define PING_H__

#include "responser.h"


class Ping: public Responser{
    HttpReq*    req = nullptr;
    HttpRes*    res = nullptr;
    uint16_t    id = 0;
    uint16_t    seq = 0;
    sa_family_t family = 0;
    bool        iserror = false;
    void Send(void* buff, size_t size);
public:
    Ping(const char *host, uint16_t id);
    explicit Ping(HttpReqHeader* req);
    virtual void request(HttpReq* req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param) override;
};
#endif
