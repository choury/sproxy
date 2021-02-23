#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "common/base.h"
#include "prot/http_pack.h"

class Responser;

class Requester: public Server{
    char source[INET6_ADDRSTRLEN];
protected:
    void init(RWer* rwer);
public:
    explicit Requester(RWer* rwer);

    virtual const char *getsrc();
    virtual const char *getid();
    virtual void response(void* index, HttpRes* res) = 0;
};

#endif
