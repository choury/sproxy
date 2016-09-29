#ifndef GUEST_S2_H__
#define GUEST_S2_H__

#include "requester.h"
#include "http2.h"
#include "binmap.h"
#include "ssl_abstract.h"

class Guest_s2: public Requester, public Http2Res{
    uint32_t lastrecv  = 0;
    binmap<Peer *, int> idmap;
    std::set<Peer *> waitlist;
    Ssl *ssl;
protected:
    virtual void defaultHE(uint32_t events)override;
    
    virtual ssize_t Read(void *buff, size_t size)override;
    virtual ssize_t Write(const void *buff, size_t size)override;
    virtual void SendFrame(Http2_header *header)override;
    virtual void GoawayProc(Http2_header *header)override;
    virtual void response(HttpResHeader& res)override;
    virtual void DataProc(const Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual void RstProc(uint32_t id, uint32_t errcode)override;
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)override;
    virtual void ErrProc(int errcode)override;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff)override;
public:
    explicit Guest_s2(int fd, const char *ip, uint16_t port, Ssl *ssl);
    explicit Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl *ssl);
    
    virtual void clean(uint32_t errcode, Peer *who, uint32_t id = 0)override;

    virtual ssize_t Write(void *buff, size_t size, Peer *who, uint32_t id=0)override;
    
    virtual int32_t bufleft(Peer*)override;
    virtual void wait(Peer *who)override;
    virtual void writedcb(Peer *who)override;
    virtual int showerrinfo(int ret, const char *);
//    virtual int showstatus(char *buff, Peer *who)override;
    void check_alive();
};

#endif
