#ifndef __GUEST_H__
#define __GUEST_H__

#include <netinet/in.h>

#include "peer.h"


class Guest:public Peer {
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    char destip[INET6_ADDRSTRLEN];
    uint16_t  destport;
    bool authorized = false;
    int showerrinfo(int ret, const char *)override;
    virtual void defaultHE(uint32_t events);
    void closeHE(uint32_t events)override;
    void ReqProc(HttpReqHeader &req)override;
    ssize_t DataProc(const void *buff, size_t size)override;
public:
    Guest();
    explicit Guest(int fd);
    virtual void Response(HttpResHeader& res);
};

#endif
