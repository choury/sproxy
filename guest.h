#ifndef GUEST_H__
#define GUEST_H__

#include "peer.h"
#include "http.h"
#include <netinet/in.h>

class Guest:public Peer, public HttpRes{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;

    virtual int showerrinfo(int ret, const char *)override;
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events)override;
    
    virtual ssize_t Read(void* buff, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual ssize_t DataProc(const void *buff, size_t size)override;
public:
#define ISCONNECT_F     1
#define ISCHUNKED_F     2
    char flag;
    explicit Guest(int fd, struct sockaddr_in6 *myaddr);
    explicit Guest(const Guest *const copy);
    virtual ~Guest();
    virtual ssize_t Write(const void* buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual void Response(HttpResHeader& res, Peer* who);
    virtual int showstatus(char *buff, Peer* who)override;
};

#endif
