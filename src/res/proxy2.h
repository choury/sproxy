#ifndef PROXY2_H__
#define PROXY2_H__

#include "responser.h"
#include "prot/http2.h"

struct ReqStatus{
    std::weak_ptr<Requester> req_ptr;
    void*      req_index;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
    uint32_t   req_flags;
};

class Proxy2:public Responser, public Http2Requster {
    std::map<uint32_t, ReqStatus> statusmap;
#ifdef __ANDROID__
    uint32_t receive_time;
    uint32_t ping_time;
#else
    Job* ping_check_job = nullptr;
#endif
    Job* connection_lost_job = nullptr;
protected:
    void ping_check();
    void connection_lost();
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void PingProc(const Http2_header *header)override;
    virtual void GoawayProc(const Http2_header * header) override;
    virtual void ResProc(HttpResHeader* res)override;
    virtual void PushFrame(Http2_header *header)override;
    virtual void DataProc(uint32_t id, const void *data, size_t len)override;
    virtual void EndProc(uint32_t id) override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void ErrProc(int errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
    virtual void ShutdownProc(uint32_t id)override;


    virtual std::list<write_block>::insert_iterator queue_head() override;
    virtual std::list<write_block>::insert_iterator queue_end() override;
    virtual void queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) override;
public:
    explicit Proxy2(RWer* rwer);
    virtual ~Proxy2() override;


    virtual int32_t bufleft(void* index)override;
    virtual void Send(const void *buff, size_t size, void* index)override;
    virtual void writedcb(const void* index)override;
    virtual int finish(uint32_t flags, void* index)override;
    
    virtual void* request(HttpReqHeader* req)override;
    
    virtual void dump_stat(Dumper dp, void* param) override;

    std::weak_ptr<Proxy2> init(HttpReqHeader* req);
    void flush();
};

extern std::weak_ptr<Proxy2> proxy2;
void flushproxy2(int force);

#endif