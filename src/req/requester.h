#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "base.h"
#include "prot/http_pack.h"

class Responser;

class Requester: public Server{
    char sourceip[INET6_ADDRSTRLEN];
public:
    explicit Requester(RWer* rwer);

    virtual const char *getsrc();
    virtual const char *getip();
    virtual void response(void* index, HttpRes* res) = 0;
};

#endif
