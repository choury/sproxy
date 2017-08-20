#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <list>

class Guest:public Requester, public HttpResponser {
    Buffer buffer;
protected:
    Responser* responser_ptr = nullptr;
    void*      responser_index = nullptr;
#define GUEST_IDELE_F        0
#define GUEST_PROCESSING_F   (1<<1)
#define GUEST_CONNECT_F      (1<<2)
#define GUEST_SEND_F         (1<<3)
#define GUEST_CHUNK_F        (1<<4)
#define GUEST_REQ_COMPLETED  (1<<5)
#define GUEST_RES_COMPLETED  (1<<6)
    uint32_t Status_flags = GUEST_IDELE_F;

    virtual void defaultHE(uint32_t events)override;
    virtual void closeHE(uint32_t) override;
    virtual void deleteLater(uint32_t errcode) override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ReqProc(HttpReqHeader* req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual bool EndProc() override;
    virtual void ErrProc(int errcode)override;
    virtual void discard() override;
public:
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);

    virtual int32_t bufleft(void * index) override;
    virtual ssize_t Send(void* buff, size_t size, void* index)override;

    virtual void response(HttpResHeader* res)override;
    virtual void transfer(void* index, Responser* res_ptr, void* res_index)override;

    virtual bool finish(uint32_t flags, void* index)override;
    virtual void writedcb(void * index) override;
    virtual const char* getsrc(void *)override;
    virtual void dump_stat()override;
};

#endif
