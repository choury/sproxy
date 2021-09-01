#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "misc/config.h"
#include "prot/http/http.h"

class Requester;

struct HStatus{
    HttpReq* req;
    HttpRes* res;
    uint     flags;
};

class Host:public Responser, public HttpRequester {
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    struct Destination Server;
    HStatus status{};

    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ResProc(HttpResHeader* res)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc() override;

    virtual void request(HttpReq* req, Requester*) override;
    virtual void connected();
    void Send(PREPTR void* buff, size_t size);
    void reply();
public:
    explicit Host(const Destination* dest);
    virtual ~Host() override;
    
    virtual void dump_stat(Dumper dp, void* param) override;
    static void gethost(HttpReq* req, const Destination* dest, Requester* src);
};

#endif
