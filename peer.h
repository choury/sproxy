#ifndef __PEER_H__
#define __PEER_H__

#include <stdint.h>
#include <map>

#include "con.h"
#include "http.h"
#include "common.h"

/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


class Bindex{
    std::map<void *,void *> map;
public:
    void add(void *key1,void *key2);
    void del(void *key1,void *key2);
    void del(void *key);
    void *query(void *key);
};

extern Bindex bindex;

class Peer:public Con,public Http{
protected:
    int fd;
    size_t  writelen=0;
    uchar wbuff[1024 * 1024];
    Peer(int fd=0,Http::Initstate state=HTTPHEAD);
    virtual ssize_t Read(void *buff,size_t size)override;
    virtual void ErrProc(int errcode)override;
    virtual ssize_t Write();
    virtual void closeHE(uint32_t events)=0;
public:
    virtual void clean(Peer *who);
    virtual ssize_t Write(Peer* who,const void *buff,size_t size);
    virtual void writedcb();
    virtual size_t bufleft();
    virtual int showerrinfo(int ret,const char * )=0;
    virtual ~Peer();
};


#endif