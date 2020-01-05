#ifndef HOST_H__
#define HOST_H__

#include "responser.h"
#include "misc/config.h"
#include "prot/http.h"

class Requester;

class Host:public Responser, public HttpRequester {
    size_t rx_bytes = 0;
    size_t tx_bytes = 0;
protected:
    struct Destination Server;
    HttpReqHeader* req = nullptr;
    
    virtual void deleteLater(uint32_t errcode) override;
    virtual void Error(int ret, int code);
    
    virtual void ResProc(HttpResHeader* res)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
    virtual void EndProc() override;
    virtual void ErrProc()override;

    virtual void* request(HttpReqHeader* req)override;
    virtual void connected();
public:
    explicit Host(const Destination* dest);
    virtual ~Host() override;
    
    virtual int32_t bufleft(void*) override;
    virtual void Send(void* buff, size_t size, void* index)override;

    virtual int finish(uint32_t flags, void* index)override;
    virtual void writedcb(const void * index) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    static std::weak_ptr<Responser> gethost(const Destination* dest, HttpReqHeader* req, std::weak_ptr<Responser> responser_ptr);
};

#endif
