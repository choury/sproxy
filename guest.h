#ifndef __GUEST_H__
#define __GUEST_H__

#include <netinet/in.h>

#include "peer.h"


class Guest:public Peer{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    char destip[INET6_ADDRSTRLEN];
    uint16_t  destport;
    virtual int showerrinfo(int ret,const char * )override;
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    virtual void ReqProc(HttpReqHeader &req)override;
    virtual ssize_t DataProc(const void *buff,size_t size)override;
public:
    Guest();
    Guest(int fd);
    virtual void connected();
};


#endif