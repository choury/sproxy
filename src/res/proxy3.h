#ifndef PROXY3_H__
#define PROXY3_H__

#include "responser.h"
#include "prot/http3/http3.h"
#include "prot/quic/quicio.h"


class Proxy3:public Responser, public Http3Requster {
    struct ReqStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        uint32_t flags;
    };

    std::map<uint64_t, ReqStatus> statusmap;
    uint64_t maxDataId = 0;
    Job* idle_timeout = nullptr;
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ResProc(uint64_t id, std::shared_ptr<HttpResHeader> res)override;
    virtual void PushFrame(Buffer&& bb)override;
    virtual bool DataProc(uint64_t id, const void *data, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual uint64_t CreateUbiStream() override;

    void Recv(Buffer&& bb);
    void Handle(uint64_t id, ChannelMessage::Signal s);
    void RstProc(uint64_t id, uint32_t errcode);
    void Clean(uint64_t id, ReqStatus& status, uint32_t errcode);
public:
    explicit Proxy3(std::shared_ptr<QuicRWer> rwer);
    virtual ~Proxy3() override;

    virtual void request(std::shared_ptr<HttpReq> req, Requester*)override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;

    void init(std::shared_ptr<HttpReq> req);
};

#endif
