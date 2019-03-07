#ifndef GUEST2_H__
#define GUEST2_H__

#include "requester.h"
#include "prot/http2.h"

struct ResStatus{
    std::weak_ptr<Responser> res_ptr;
    void*      res_index;
    int32_t remotewinsize; //对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize; //发送给对端的窗口大小，接受时减小，给对端发送update时增加
    uint32_t res_flags;
};

class Guest2: public Requester, public Http2Responser {
    std::map<uint32_t, ResStatus> statusmap;
    void init(RWer* rwer);
protected:
    int connection_lost();
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
#ifndef NDEBUG
    virtual void PingProc(const Http2_header *header)override;
#endif
    virtual void GoawayProc(const Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader* req)override;
    virtual void DataProc(uint32_t id, const void* data, size_t len)override;
    virtual void EndProc(uint32_t id) override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void ErrProc(int errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;

    virtual std::list<write_block>::insert_iterator queue_head() override;
    virtual std::list<write_block>::insert_iterator queue_end() override;
    virtual void queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) override;
public:
    explicit Guest2(const char *ip, uint16_t port, RWer* rwer);
    explicit Guest2(const sockaddr_un* addr, RWer* rwer);
    virtual ~Guest2();
    

    virtual int32_t bufleft(void* index)override;
    virtual void Send(const void* buff, size_t size, void* index)override;
    virtual void writedcb(const void* index)override;
    virtual void finish(uint32_t flags, void* index)override;
    
    virtual void response(HttpResHeader* res)override;
    virtual void transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index)override;

    virtual const char* getsrc(const void *)override;
    virtual void dump_stat(Dumper dp, void* param) override;

};

#endif
