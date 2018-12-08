#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "base.h"
#include "prot/http_pack.h"

class Responser;

class Requester: public Peer{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
public:
    explicit Requester(const sockaddr_un *myaddr = nullptr);
    explicit Requester(const char *ip, uint16_t port);
    
    virtual const char *getsrc(const void* index) = 0;
    virtual const char *getip();
    virtual void response(HttpResHeader* res) = 0;
    virtual void transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index) = 0;
};

#endif
