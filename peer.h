#ifndef __PEER_H__
#define __PEER_H__

#include <stdint.h>
#include <map>

#include "con.h"
#include "common.h"

/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


class Bindex{
    std::map<void *,void *> map;
public:
    void add(void *key1,void *key2);
    void del(void *key1,void *key2);
    void *query(void *key);
};

extern Bindex bindex;

class Peer:public Con{
protected:
    int  fd;
    char wbuff[1024 * 1024];
    int  write_len=0;
    Peer();  //do nothing
    Peer(int fd);
    virtual int Write();
    virtual int Read(void *buff,size_t size);
    virtual void clean(Peer *who)=0;
public:
    virtual void writedcb();
    virtual int Write(Peer* who,const void *buff,size_t size);
    virtual size_t bufleft();
    virtual int showerrinfo(int ret,const char * )=0;
    virtual ~Peer();
};


#endif