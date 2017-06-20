#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <list>

class Guest:public Requester, public HttpResponser {
    Buffer buffer;
protected:
    enum class Status{
        idle, connect_method, send_method, head_methon, chunked,
    } status = Status::idle;
    uint8_t flag = 0;
    Responser* responser_ptr = nullptr;
    void*      responser_index = nullptr;

    virtual void defaultHE(uint32_t events)override;
    virtual void closeHE(uint32_t events) override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader* req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual int32_t bufleft(void * index) override;
    virtual ssize_t Send(void* buff, size_t size, void* index)override;

    virtual void response(HttpResHeader* res)override;
    virtual void transfer(void* index, Responser* res_ptr, void* res_index)override;

    virtual void clean(uint32_t errcode, void* index)override;
    virtual const char* getsrc(void *)override;
    virtual void dump_stat()override;
};

#endif
