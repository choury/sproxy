#ifndef PROXY3_H__
#define PROXY3_H__

#include "responser.h"
#include "prot/http3/http3.h"
#include "misc/job.h"

class QuicRWer;
class Proxy3:public Responser, public Http3Requster {
    struct ReqStatus{
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
        uint32_t flags;
        Job      cleanJob = nullptr; 
    };

    std::map<uint64_t, ReqStatus> statusmap;
    uint64_t maxDataId = 0;
    Job idle_timeout = nullptr;
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ResProc(uint64_t id, std::shared_ptr<HttpResHeader> res)override;
    virtual void SendData(Buffer&& bb)override;
    virtual bool DataProc(Buffer& bb)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual uint64_t CreateUbiStream() override;

    void RstProc(uint64_t id, uint32_t errcode);
    void Clean(uint64_t id, uint32_t errcode);
public:
    explicit Proxy3(std::shared_ptr<QuicRWer> rwer);
    virtual ~Proxy3() override;

    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester*)override;
    virtual bool reconnect() override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;

    void init(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);
};

#endif
