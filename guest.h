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
    char rbuff[4096];
    uint32_t  read_len=0;
    uint32_t expectlen=0;
public:
    Host *host=nullptr;
    Guest(int fd,int efd);
    virtual void clean() override;
    virtual void handleEvent(uint32_t events) override;
    virtual void connected();
};


#endif