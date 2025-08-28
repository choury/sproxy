#ifndef UHOST_H__
#define UHOST_H__

#include "responser.h"
#include "misc/job.h"

class Uhost: public Responser{
    struct {
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
    }status;
    char hostname[DOMAINLIMIT];
    uint16_t port;
    bool is_closing = false;
    bool is_responsed = false;
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
    size_t rx_dropped = 0;
    Job    idle_timeour = nullptr;
public:
    Uhost(const Destination& dest);
    explicit Uhost(std::shared_ptr<HttpReqHeader> req);
    virtual ~Uhost() override;
    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};
#endif
