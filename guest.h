#ifndef GUEST_H__
#define GUEST_H__

#include "peer.h"
#include "http.h"
#include <netinet/in.h>

class Guest:public Peer, public HttpRes{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    Ptr responser_ptr;

    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events)override;
    
    virtual Ptr shared_from_this() override;
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
    using Peer::Write;
#define ISPERSISTENT_F     1
#define ISCHUNKED_F        2
    char flag;
    explicit Guest(Guest&& copy);
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);
    virtual ~Guest();

    virtual int showerrinfo(int ret, const char *)override;
    virtual ssize_t Write(void* buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual const char *getsrc();
    virtual const char *getip();
    virtual void response(HttpResHeader& res);
};

#endif
