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
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ResProc(uint64_t id, HttpResHeader* res)override;
    virtual void PushFrame(uint64_t id, PREPTR void* buff, size_t len)override;
    virtual void DataProc(uint64_t id, const void *data, size_t len)override;
    virtual void RstProc(uint64_t id, uint32_t errcode)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual void ShutdownProc(uint64_t id)override;
    virtual uint64_t CreateUbiStream() override;

    void Send(uint64_t id ,const void* buff, size_t size);
    void Clean(uint64_t id, ReqStatus& status, uint32_t errcode);

    bool wantmore(const ReqStatus& status);
public:
    explicit Proxy3(std::shared_ptr<QuicRWer> rwer);
    virtual ~Proxy3() override;

    virtual void request(std::shared_ptr<HttpReq> req, Requester*)override;

    virtual void dump_stat(Dumper dp, void* param) override;

    void init(std::shared_ptr<HttpReq> req);
    void flush();
};

extern Proxy3* proxy3;
#endif
