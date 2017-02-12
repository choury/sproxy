#ifndef REQUESTER_H__
#define REQUESTER_H__

#include "peer.h"
#include "prot/parse.h"

class Responser;

class Requester: public Peer{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    virtual void defaultHE(uint32_t events) = 0;
    virtual void closeHE(uint32_t events) override;
public:
    explicit Requester(int fd, struct sockaddr_in6 *myaddr = nullptr);
    explicit Requester(int fd, const char *ip, uint16_t port);
    
    virtual const char *getsrc();
    virtual const char *getip();
    virtual void ResetResponser(Responser *r, void* index);
    virtual void response(HttpResHeader&& res) = 0;
};

#endif
