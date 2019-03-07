#ifndef BASE_H__
#define BASE_H__

#include "common.h"
#include "prot/rwer.h"
#include <queue>
#include <list>
#include <functional>

#include <string.h>

class Server: virtual public RwObject  {
protected:
    RWer* rwer = nullptr;
public:
    explicit Server();
    virtual ~Server() override;
    virtual void deleteLater(uint32_t errcode);
    virtual void dump_stat(Dumper dp, void* param) = 0;
};

class Peer:public Server{
public:
    virtual int32_t bufleft(void* index) = 0;
    virtual void Send(const void *buff, size_t size, void* index);
    virtual void Send(void* buff, size_t size, void* index);
    virtual void finish(uint32_t flags, void* info) = 0;

    virtual void writedcb(const void* index);
};

void flushproxy2(bool force);
void releaseall();
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);
void dump_stat(Dumper dp, void* param);

#endif
