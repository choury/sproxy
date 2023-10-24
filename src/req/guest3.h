//
// Created by 周威 on 2022/3/18.
//

#ifndef SPROXY_GUEST3_H
#define SPROXY_GUEST3_H

#include "requester.h"
#include "prot/quic/quicio.h"
#include "prot/http3/http3.h"
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
    bool mitmProxy = false;
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> res)override;
    virtual void PushFrame(Buffer&& bb)override;
    virtual bool DataProc(uint64_t id, const void *data, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual uint64_t CreateUbiStream() override;

    void init();
    void connected();
    void Recv(Buffer&& bb);
    void Handle(uint64_t id, ChannelMessage::Signal s);
    void RstProc(uint64_t id, uint32_t errcode);
    void Clean(uint64_t id, uint32_t errcode);
public:
    //explicit Guest3(int fd, const sockaddr_storage* addr, SSL_CTX* ctx, QuicMgr* quicMgr);
    explicit Guest3(std::shared_ptr<QuicRWer> rwer);
    explicit Guest3(std::shared_ptr<QuicMer> rwer);
    virtual ~Guest3() override;

    void AddInitData(const void* buff, size_t len);
    virtual void response(void* index, std::shared_ptr<HttpRes> res) override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif //SPROXY_GUEST3_H
