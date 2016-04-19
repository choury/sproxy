#ifndef PEER_H__
#define PEER_H__

#include "con.h"
#include "common.h"
#include <queue>
#include <set>

/* guest   ---   (client) --- host(proxy)
 * guest_s ---   (server) --- host/file/cgi */

#define WRITE_NOTHING     1
#define WRITE_INCOMP      2
#define WRITE_COMPLETE    3

struct write_block{
    void * buff;
    size_t len;
    size_t wlen;
};


class Peer:public Con{
    size_t  writelen = 0;
    std::queue<write_block> write_queue;
protected:
    int fd;
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write(const void *buff, size_t size);
    virtual int Write();
    virtual void closeHE(uint32_t events);
public:
    virtual ~Peer();
    int32_t remotewinsize = 65535; //(for http2) 对端提供的窗口大小，发送时减小，收到对段update时增加
    int32_t localwinsize = 65535; //(for http2) 发送给对端的窗口大小，接受时减小，给对端发送update时增加
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0);
    virtual ssize_t Write(const void *buff, size_t size, Peer*, uint32_t id = 0);
    virtual ssize_t Write(void *buff, size_t size, Peer*, uint32_t id = 0);
    virtual int showerrinfo(int ret, const char *) = 0;
    
    virtual void writedcb(Peer* who);
    virtual int32_t bufleft(Peer* who);
    virtual void wait(Peer* who);
};

class Guest;
void connect(Guest *p1, Peer *p2);
Guest *queryconnect(Peer *key);
Peer *queryconnect(Guest *key);
std::set<std::pair<Guest *, Peer *>> disconnect(Peer *k1, Peer* k2);

#endif
