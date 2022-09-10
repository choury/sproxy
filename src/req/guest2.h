#ifndef GUEST2_H__
#define GUEST2_H__

#include "requester.h"
#include "prot/http2/http2.h"


class Guest2: public Requester, public Http2Responser {
    struct ReqStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        int32_t  remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
        int32_t  localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
        uint32_t flags;
    };
    std::map<uint32_t, ReqStatus> statusmap;
    //void init(RWer* rwer);
    Job* connection_lost_job = nullptr;
protected:
    void connection_lost();
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
#ifndef NDEBUG
    virtual void PingProc(const Http2_header *header)override;
#endif
    virtual void GoawayProc(const Http2_header *header)override;
    virtual void ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> req)override;
    virtual void DataProc(uint32_t id, const void* data, size_t len)override;
    virtual void EndProc(uint32_t id) override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void ErrProc(int errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;

    virtual std::list<Buffer>::insert_iterator queue_head() override;
    virtual std::list<Buffer>::insert_iterator queue_end() override;
    virtual void queue_insert(std::list<Buffer>::insert_iterator where, Buffer&& wb) override;

    void Recv(Buffer&& bb);
    void Handle(uint32_t id, ChannelMessage::Signal signal);
    void Clean(uint32_t id, uint32_t errcode);
    static bool wantmore(const ReqStatus& status);
public:
    explicit Guest2(std::shared_ptr<RWer> rwer);
    virtual ~Guest2();
    
    virtual void response(void* index, std::shared_ptr<HttpRes> res)override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif
