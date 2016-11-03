#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "http.h"
#include <netinet/in.h>
#include <queue>

class Guest:public Requester, public HttpResponser {
    void request_next();
protected:
    enum {none, requesting, presistent, chunked} status = none;
    Responser* responser_ptr = nullptr;
    std::queue<HttpReq> reqs;

    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader& req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
    using Peer::Write;
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual void ResetResponser(Responser *r)override;
    virtual void discard()override;
    virtual ssize_t Write(void* buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual void response(HttpResHeader& res)override;
    friend void guesttick(Guest * guest);
};

#endif
