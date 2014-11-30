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
    size_t  writelen=0;
    size_t  readlen=0;
    uchar wbuff[1024 * 1024];
    uchar rbuff[HEADLENLIMIT];
    Peer();  //do nothing
    Peer(int fd);
    virtual ssize_t Read(void *buff,size_t size);
    virtual ssize_t Write();
public:
    virtual void clean(Peer *who)=0;
    virtual ssize_t Write(Peer* who,const void *buff,size_t size);
    virtual void writedcb();
    virtual size_t bufleft();
    virtual int showerrinfo(int ret,const char * )=0;
    virtual ~Peer();
};


#endif