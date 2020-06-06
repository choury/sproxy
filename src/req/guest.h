#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include <netinet/in.h>
#include <openssl/ssl.h>

struct GStatus{
    HttpReq*  req;
    HttpRes*  res;
    uint      flags;
};

class Guest:public Requester, public HttpResponser {
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    std::list<GStatus>       statuslist;
    void ReadHE(size_t len);
    void WriteHE(size_t len);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ReqProc(HttpReqHeader* req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc() override;
    void Send(void* buff, size_t len);
    void deqReq();
public:
    explicit Guest(int fd, const sockaddr_un *myaddr);
    explicit Guest(int fd, const sockaddr_un *myaddr, SSL_CTX* ctx);
    ~Guest();


    virtual void response(void*, HttpRes* res)override;

    virtual const char* getsrc()override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

#endif
