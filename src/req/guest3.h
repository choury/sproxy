//
// Created by 周威 on 2022/3/18.
//

#ifndef SPROXY_GUEST3_H
#define SPROXY_GUEST3_H

#include "requester.h"
#include "prot/http3/http3.h"
#include "prot/quic/quic_mgr.h"
#include "misc/net.h"
#include "misc/config.h"

#include <errno.h>

class Guest3: public Requester, public Http3Responser {
    struct ReqStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        uint32_t flags;
    };

    std::map<uint64_t, ReqStatus> statusmap;
    uint64_t maxDataId = 0;
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> res)override;
    virtual void PushFrame(Buffer&& bb)override;
    virtual void DataProc(uint64_t id, const void *data, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual uint64_t CreateUbiStream() override;

    void Recv(Buffer&& bb);
    void Handle(uint64_t id, ChannelMessage::Signal s);
    void RstProc(uint64_t id, uint32_t errcode);
    void Clean(uint64_t id, uint32_t errcode);
public:
    explicit Guest3(int fd, const sockaddr_storage* addr, SSL_CTX* ctx, QuicMgr* quicMgr);
    virtual ~Guest3() override;

    void AddInitData(const void* buff, size_t len);
    virtual void response(void* index, std::shared_ptr<HttpRes> res) override;

    virtual void dump_stat(Dumper dp, void* param) override;
};

class Quic_server: public Ep {
    SSL_CTX *ctx = nullptr;
    QuicMgr quicMgr;

    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Http server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            struct sockaddr_storage myaddr;
            socklen_t temp = sizeof(myaddr);
            memset(&myaddr, 0, temp);
            char buff[max_datagram_size];
            ssize_t ret = recvfrom(getFd(), buff, sizeof(buff), 0, (sockaddr*)&myaddr, &temp);
            if(ret < 0){
                LOGE("recvfrom error: %s\n", strerror(errno));
                return;
            }
            quicMgr.PushDate(getFd(), &myaddr, ctx, buff, ret);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Quic_server() override{
        if(ctx){
            SSL_CTX_free(ctx);
        }
    };
    Quic_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Quic_server::defaultHE;
    }
};

#endif //SPROXY_GUEST3_H
