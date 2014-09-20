#ifndef __HOST_H__
#define __HOST_H__

#include "peer.h"
#include "net.h"

class Guest;

class Host:public Peer{
    char hostname[DOMAINLIMIT];
    int targetport;
protected:
public:
    Guest* guest;
    Host(int efd,Guest *guest,const char *hostname,int port);
    virtual bool candelete()override;
    virtual void handleEvent(uint32_t events)override;
    virtual void clean() override;
    static Host *gethost(Host *exist,const char *host,int port,int efd,Guest *guest);
    friend void connectHost(Host * host);
};

#endif