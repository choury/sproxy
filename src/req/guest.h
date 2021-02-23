#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http.h"
#include "misc/net.h"

#include <errno.h>
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
    std::list<GStatus> statuslist;
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
    explicit Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx);
    ~Guest();

    virtual void response(void*, HttpRes* res)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

template<class T>
class Http_server: public Ep {
    SSL_CTX *ctx = nullptr;
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Http server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_storage myaddr;
            socklen_t temp = sizeof(myaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&myaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&myaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            SetTcpOptions(clsk, &myaddr);
            new T(clsk, &myaddr, ctx);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Http_server() override{
        if(ctx){
            SSL_CTX_free(ctx);
        }
    };
    Http_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Http_server::defaultHE;
    }
};

#endif
