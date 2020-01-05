#ifndef PING_H__
#define PING_H__

#include "responser.h"


class Ping: public Responser{
    std::weak_ptr<Requester> req_ptr;
    void*       req_index = nullptr;
    char        hostname[DOMAINLIMIT];
    uint16_t    id = 0;
    uint16_t    seq = 0;
    bool        iserror = false;
    sockaddr_un addr;
    virtual void deleteLater(uint32_t errcode) override;
public:
    Ping(const char *host, uint16_t id);
    explicit Ping(HttpReqHeader* req);
    virtual void* request(HttpReqHeader* req) override;
    virtual void Send(void* buff, size_t size, void* index)override;

    virtual int32_t bufleft(void* index)override;
    virtual int finish(uint32_t flags, void* index)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};
#endif
