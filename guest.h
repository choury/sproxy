#ifndef __GUEST_H__
#define __GUEST_H__

#include <netinet/in.h>


#include "peer.h"
#include "common.h"


class Guest:public Peer{
protected:
    char rbuff[HEADLENLIMIT];
    size_t readlen=0;
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    char destip[INET6_ADDRSTRLEN];
    uint16_t  destport;
    uint32_t expectlen=0;
    virtual int showerrinfo(int ret,const char * )override;
    virtual void getheaderHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void postHE(uint32_t events);
    virtual void closeHE(uint32_t events);
public:
    Guest();
    Guest(int fd);
    virtual void connected(const char *method);
};


#endif