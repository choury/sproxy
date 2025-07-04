#ifndef GUEST_H__
#define GUEST_H__

#include "requester.h"
#include "prot/http/http.h"
#include "misc/net.h"
#include "misc/config.h"
#include "misc/job.h"
#include "prot/tls.h"

#include <netinet/in.h>
#include <openssl/ssl.h>

class MemRWer;
class Guest:public Requester, public HttpResponser {
protected:
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
    struct ReqStatus{
        std::shared_ptr<HttpReqHeader>  req;
        std::shared_ptr<MemRWer>        rw;
        std::shared_ptr<IMemRWerCallback> cb;
        uint      flags = 0;
        Job       cleanJob = nullptr;
    };
    std::list<ReqStatus> statuslist;
    bool headless = false;
    size_t ReadHE(Buffer&& bb);
    void WriteHE(uint64_t id);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);

    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> req)override;
    virtual ssize_t DataProc(Buffer& bb)override;
    virtual void EndProc(uint64_t id) override;
    virtual void ErrProc(uint64_t id) override;
    size_t Recv(Buffer&& bb);
    virtual std::shared_ptr<IMemRWerCallback> response(uint64_t id) override;
    void deqReq();
public:
    explicit Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx);
    explicit Guest(std::shared_ptr<RWer> rwer);
    virtual ~Guest() override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

template<class T>
class Http_server: public Ep {
    SSL_CTX *ctx = nullptr;
    uint ssl_cert_version = 0;
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Http server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            if (ctx && ssl_cert_version != opt.cert_version) {
                SSL_CTX_free(ctx);
                ctx = initssl(false, nullptr);
                ssl_cert_version = opt.cert_version;
                LOG("SSL context updated due to certificate reload (version %u)\n", ssl_cert_version);
            }
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
