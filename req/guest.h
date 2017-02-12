#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <queue>

class Guest:public Requester, public HttpResponser {
    void request_next();
protected:
    enum class Status{
        none, requesting, presistent, chunked,
    } status = Status::none;
    Responser* responser_ptr = nullptr;
    void*      responser_index = nullptr;
    std::queue<HttpReq> reqs;

    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader&& req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void discard()override;
public:
    using Peer::Write_buff;
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual void ResetResponser(Responser *r, void* index)override;
    virtual ssize_t Write(void* buff, size_t size, void* index)override;
    virtual void clean(uint32_t errcode, void* index)override;
    virtual void response(HttpResHeader&& res)override;
    friend void request_next(Guest * guest);
};

#endif
