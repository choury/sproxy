#ifndef STATUS_H__
#define STATUS_H__

#include "responser.h"


class Status: public Responser{
public:
    Status();
    virtual void* request(HttpReqHeader* req) override;

    virtual void Send(const void *buff, size_t size, void* index)override;
    virtual void Send(void *buff, size_t size, void* index)override;
    virtual int32_t bufleft(void* index)override;
    virtual void finish(uint32_t flags, void* index)override;
    virtual void dump_stat(Dumper dp, void* param)override;
};
#endif
