#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "misc/config.h"
#include "prot/http/http.h"

class Requester;


class Host:public Responser, public HttpRequester {
    struct ReqStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        uint     flags = 0;
    } status{};

    struct Destination Server;
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ResProc(std::shared_ptr<HttpResHeader> res)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc() override;

    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
    virtual void connected();
    void Recv(Buffer&& bb);
    void Handle(ChannelMessage::Signal s);
    void reply();
public:
    explicit Host(const Destination* dest);
    virtual ~Host() override;
    
    virtual void dump_stat(Dumper dp, void* param) override;
    static void gethost(std::shared_ptr<HttpReq> req, const Destination* dest, Requester* src);
};

#endif
