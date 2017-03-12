#ifndef PEER_H__
#define PEER_H__

#include "con.h"
#include "common.h"
#include <queue>

/* guest   ---   (client) --- host(proxy)
 * guest_s ---   (server) --- host/file/cgi */

#define WRITE_NOTHING     1
#define WRITE_INCOMP      2
#define WRITE_COMPLETE    3

struct write_block{
    void* buff;
    size_t len;
    size_t wlen;
};


class Peer:public Con{
    std::queue<write_block> write_queue;
    size_t  writelen = 0;
protected:
    explicit Peer(int fd = 0);
    virtual ssize_t Read(void *buff, size_t size);
    virtual ssize_t Write(const void *buff, size_t size);
    virtual ssize_t push_buff(void* buff, size_t size);
    virtual int Write_buff();
    
    virtual void closeHE(uint32_t events) = 0;
public:
    virtual ~Peer();
    
    virtual void clean(uint32_t errcode, void* info);
    
    virtual ssize_t Write(const void *buff, size_t size, void* index);
    virtual ssize_t Write(void* buff, size_t size, void* index);
    
    virtual void wait(void* index);
    virtual void writedcb(void* index);
    virtual int32_t bufleft(void* index);
};

#endif
