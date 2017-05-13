#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <list>

class Guest:public Requester, public HttpResponser {
    void request_next();
protected:
    enum class Status{
        idle, requesting, presistent, chunked, headonly,
    } status = Status::idle;
    Responser* responser_ptr = nullptr;
    void*      responser_index = nullptr;
    std::list<HttpReq> reqs;

    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader&& req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
    using Peer::Write_buff;
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual ssize_t Write(void* buff, size_t size, void* index)override;
    virtual void clean(uint32_t errcode, void* index)override;
    virtual void response(HttpResHeader&& res)override;
    virtual void dump_stat()override;
    friend void request_next(Guest * guest);
};

#endif
