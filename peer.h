#ifndef __PEER_H__
#define __PEER_H__

#include <stdint.h>

#include "common.h"

/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


enum Status {preconnect_s,accept_s,start_s, post_s , connect_s,wantclose_s, close_s ,wait_s,proxy_s};

class Peer{
protected:
    int  fd;
    int  efd;
    enum Status status=start_s;
    char wbuff[1024 * 1024];
    int  write_len=0;
    bool fulled=false;
    virtual void clean()=0;
    virtual int Write();
public:
    Peer();  //do nothing
    Peer(int fd,int efd);
    virtual void handleEvent(uint32_t events)=0;
    virtual bool candelete()=0;
    virtual void peercanwrite();
    virtual int Read(char *buff,size_t size);
    virtual int Write(const char *buff,size_t size);
    virtual size_t bufleft();
    virtual ~Peer();
};


void connectHost(Host * host);

#endif