#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http/http.h"
#include "prot/memio.h"
#include "misc/net.h"
#include "misc/job.h"

#include <errno.h>
#include <netinet/in.h>
#include <openssl/ssl.h>


class Guest:public Requester, public HttpResponser {
protected:
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
    struct ReqStatus{
        std::shared_ptr<HttpReq>  req;
        std::shared_ptr<HttpRes>  res;
        std::shared_ptr<MemRWer>  rwer;
        uint      flags = 0;
        Job       cleanJob = nullptr;
    };
    std::list<ReqStatus> statuslist;
    bool headless = false;
    size_t ReadHE(Buffer&& bb);
    int mread(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal> data);
    void WriteHE(uint64_t id);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);

    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> req)override;
    virtual ssize_t DataProc(Buffer& bb)override;
    virtual void EndProc(uint64_t id) override;
    virtual void ErrProc(uint64_t id) override;
    void Recv(Buffer&& bb);
    void Handle(Signal s);
    void deqReq();
public:
    explicit Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx);
    explicit Guest(std::shared_ptr<RWer> rwer);
    ~Guest();

    virtual void response(void*, std::shared_ptr<HttpRes> res)override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
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
            struct sockaddr_storage hisaddr;
            socklen_t temp = sizeof(hisaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&hisaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&hisaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }
            LOGD(DNET, "accept %d from tcp: %s\n", clsk, storage_ntoa(&hisaddr));
            SetTcpOptions(clsk, &hisaddr);
            new T(clsk, &hisaddr, ctx);
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
