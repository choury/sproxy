#ifndef PEER_H__
#define PEER_H__

#include "con.h"
#include "common.h"

/* guest   ---   (client) --- host(proxy)
 * guest_s ---   (server) --- host/file/cgi */



class Peer:public Con{
protected:
    int fd;
    size_t  writelen = 0;
    char wbuff[1024 * 1024];
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write();
    virtual void disconnect(Peer *who, uint32_t errcode);
    virtual void closeHE(uint32_t events) = 0;
public:
    virtual ~Peer();
    ssize_t windowsize = 0; //for http2
    ssize_t windowleft;     //for http2
    virtual void clean(Peer *who, uint32_t errcode);
    virtual void disconnected(Peer *who, uint32_t errcode);
    virtual ssize_t Write(Peer* who, const void *buff, size_t size);
    virtual int showerrinfo(int ret, const char *) = 0;
    virtual int showstatus(char *buff) {return 0;}
    
    virtual void writedcb();
    virtual size_t bufleft(Peer*);
    virtual void wait(Peer *who);
};

class Guest;
void connect(Guest *p1, Peer *p2);
Peer *queryconnect(Peer *key);

#endif
