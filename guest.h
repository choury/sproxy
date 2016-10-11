#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "http.h"
#include <netinet/in.h>

class Guest:public Requester, public HttpRes{
protected:
    Responser* responser_ptr = nullptr;

    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
    using Peer::Write;
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual void ResetResponser(Responser *r)override;
    virtual void discard()override;
    virtual ssize_t Write(void* buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual void response(HttpResHeader& res)override;
};

#endif
