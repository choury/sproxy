#ifndef BASE_H__
#define BASE_H__

#include "common/common.h"
#include "prot/rwer.h"
#include <queue>
#include <list>
#include <functional>

#include <string.h>

class Server{
protected:
    RWer* rwer = nullptr;
public:
    explicit Server();
    virtual ~Server();
    virtual void deleteLater(uint32_t errcode);
    virtual void dump_stat(Dumper dp, void* param) = 0;
};

void releaseall();
void dump_stat(Dumper dp, void* param);

#endif
