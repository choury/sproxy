#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "prot/http/http.h"

class Host:public Responser, public HttpRequester {
    struct ReqStatus{
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
        uint     flags = 0;
    } status{};

    struct Destination Server;
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);

    virtual void ResProc(uint64_t, std::shared_ptr< HttpResHeader > header) override;
    virtual ssize_t DataProc(Buffer& bb)override;
    virtual void EndProc(uint64_t id) override;
    virtual void ErrProc(uint64_t id) override;

    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester*) override;
    virtual void connected(uint32_t resolved_time);
    void reply();
public:
    explicit Host(const Destination* dest);
    virtual ~Host() override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
    static void distribute(std::shared_ptr<HttpReqHeader> req,
                           const Destination& dest,
                           std::shared_ptr<MemRWer> rw,
                           Requester* src);
};

#endif
