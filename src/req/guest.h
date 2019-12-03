#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <openssl/ssl.h>

class Guest:public Requester, public HttpResponser {
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    std::weak_ptr<Responser> responser_ptr;
    void*      responser_index = nullptr;
#define GUEST_IDELE_F        0u
#define GUEST_PROCESSING_F   (1u<<1u)
#define GUEST_CONNECT_F      (1u<<2u)
#define GUEST_SEND_F         (1u<<3u)
#define GUEST_CHUNK_F        (1u<<4u)
#define GUEST_NOLENGTH_F     (1u<<5u)
#define GUEST_REQ_COMPLETED  (1u<<6u)
#define GUEST_RES_COMPLETED  (1u<<7u)
#define GUEST_ERROR_F        (1u<<8u)
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

    virtual bool finish(uint32_t flags, void* index)override;
    virtual void writedcb(const void * index) override;
    virtual const char* getsrc(const void *)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

#endif
