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
    
    virtual void clean(uint32_t errcode, uint32_t id);
    
    virtual ssize_t Write(const void *buff, size_t size, uint32_t id)final;
    virtual ssize_t Write(void* buff, size_t size, uint32_t id);
    
    virtual void wait(uint32_t id);
    virtual void writedcb(uint32_t id);
    virtual int32_t bufleft(uint32_t id);
};

#endif
