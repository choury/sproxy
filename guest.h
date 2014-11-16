#ifndef __GUEST_H__
#define __GUEST_H__

#include <netinet/in.h>


#include "peer.h"
#include "common.h"


class Guest:public Peer{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    char destip[INET6_ADDRSTRLEN];
    uint16_t  destport;
    char rbuff[HEALLENLIMIT];
    uint32_t  read_len=0;
    uint32_t expectlen=0;
    virtual int showerrinfo(int ret,const char * )override;
    virtual void connected();
    virtual void getheaderHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void postHE(uint32_t events);
    virtual void closeHE(uint32_t events);
public:
    Guest();
    Guest(int fd);
    void (Guest::*connectedcb)()=NULL;
    virtual void clean(Peer *) override;
};


#endif