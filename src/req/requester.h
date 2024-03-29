#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "common/base.h"
#include "prot/http/http_def.h"

class Responser;

class Requester: public Server{
    char source[INET6_ADDRSTRLEN];
protected:
    void init(std::shared_ptr<RWer> rwer);
public:
    explicit Requester(std::shared_ptr<RWer> rwer);

    virtual const char *getid();
    virtual void response(void* index, std::shared_ptr<HttpRes> res) = 0;
};

#endif
