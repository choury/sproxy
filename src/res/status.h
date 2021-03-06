#ifndef STATUS_H__
#define STATUS_H__

#include "responser.h"


class Status: public Responser{
public:
    Status();
    virtual void request(HttpReq* req, Requester*) override;
    virtual void dump_stat(Dumper dp, void* param)override;
};
#endif
