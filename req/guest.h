#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <openssl/ssl.h>

class Guest:public Requester, public HttpResponser {
protected:
    std::weak_ptr<Responser> responser_ptr;
    void*      responser_index = nullptr;
#define GUEST_IDELE_F        0
#define GUEST_PROCESSING_F   (1<<1)
#define GUEST_CONNECT_F      (1<<2)
#define GUEST_SEND_F         (1<<3)
#define GUEST_CHUNK_F        (1<<4)
#define GUEST_NOLENGTH_F     (1<<5)
#define GUEST_REQ_COMPLETED  (1<<6)
#define GUEST_RES_COMPLETED  (1<<7)
#define GUEST_ERROR_F        (1<<8)
    uint32_t Status_flags = GUEST_IDELE_F;

    void ReadHE(size_t len);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ReqProc(HttpReqHeader* req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc() override;
public:
    explicit Guest(int fd, const sockaddr_un *myaddr);
    explicit Guest(int fd, const sockaddr_un *myaddr, SSL_CTX* ctx);

    virtual int32_t bufleft(void * index) override;
    virtual void Send(void* buff, size_t size, void* index)override;

    virtual void response(HttpResHeader* res)override;
    virtual void transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index)override;

    virtual void finish(uint32_t flags, void* index)override;
    virtual void writedcb(const void * index) override;
    virtual const char* getsrc(const void *)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

#endif
