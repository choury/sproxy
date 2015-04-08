#ifndef PEER_H__
#define PEER_H__

#include <stdint.h>
#include <map>

#include "con.h"
#include "http.h"
#include "common.h"

/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */




class Peer:public Con{
protected:
    int fd;
    size_t  writelen = 0;
    uchar wbuff[1024 * 1024];
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write();
    virtual void closeHE(uint32_t events) = 0;
public:
    virtual void clean(Peer *who);
    virtual void tick();
    virtual ssize_t Write(Peer* who, const void *buff, size_t size);
    virtual void writedcb();
    virtual size_t bufleft();
    virtual int showerrinfo(int ret, const char *) = 0;
    virtual ~Peer();
};

class Bindex{
    std::map<Peer *, Peer *> map;
public:
    void add(Peer *key1, Peer *key2);
    void del(Peer *key1, Peer *key2);
    void del(Peer *key);
    Peer *query(Peer *key);
    void tick();
};

extern Bindex bindex;


#endif
