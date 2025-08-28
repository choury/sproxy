#ifndef PING_H__
#define PING_H__

#include "responser.h"


class Ping: public Responser{
    struct {
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
    }status{};
    uint16_t    id = 0;
    uint16_t    seq = 1;
    sa_family_t family = 0;
#define PING_IS_RAW_SOCK  1
#define PING_IS_CLOSED_F  2
#define PING_IS_RESPONSED 4
    uint32_t    flags  = 0;
public:
    Ping(const Destination& dest);
    explicit Ping(std::shared_ptr<HttpReqHeader> req);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};
#endif
