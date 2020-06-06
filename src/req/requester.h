#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "base.h"
#include "prot/http_pack.h"

class Responser;

class Requester: public Server{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
public:
    explicit Requester(const sockaddr_un *myaddr = nullptr);
    explicit Requester(const char *ip, uint16_t port);
    
    virtual const char *getsrc();
    virtual const char *getip();
    virtual void response(void* index, HttpRes* res) = 0;
};

#endif
