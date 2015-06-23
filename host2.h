#ifndef HOST2_H__
#define HOST2_H__

#include "host.h"


class Host2:public Host {
public:
    Host2(HttpReqHeader &req, Guest *guest);
    virtual void ResProc(HttpResHeader &res)override;
};

#endif