#ifndef HOST_UDP_H__
#define HOST_UDP_H__

#include "responser.h"
#include "http.h"

class Host_udp:public Responser{
protected:
    virtual Ptr shared_from_this() override;
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
public:
    explicit Host_udp();
    ~Host();
    
    virtual int showerrinfo(int ret, const char *s)override;
    virtual Ptr request(HttpReqHeader &req)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
};

#endif
