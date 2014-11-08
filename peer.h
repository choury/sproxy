#ifndef __PEER_H__
#define __PEER_H__

#include <stdint.h>

#include "con.h"

#include "common.h"

/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


enum Status {accept_s,start_s, post_s , connect_s, close_s ,wait_s,proxy_s};

class Peer:public Con{
protected:
    int  fd;
    int  efd;
    char wbuff[1024 * 1024];
    int  write_len=0;
    Peer();  //do nothing
    Peer(int fd,int efd);
    virtual int Write();
    virtual int Read(void *buff,size_t size);
    virtual void clean()=0;
    virtual void closeHE(uint32_t events);
public:
    virtual void writedcb();
    virtual int Write(const void *buff,size_t size);
    virtual size_t bufleft();
    virtual int showerrinfo(int ret,const char * )=0;
    virtual ~Peer();
};

class Guest;
class Host;

//void connectHost(Host * host);

#endif