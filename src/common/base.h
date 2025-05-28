#ifndef BASE_H__
#define BASE_H__

#include "common/common.h"
#include "prot/rwer.h"
#include <memory>


class Server{
protected:
    std::shared_ptr<RWer> rwer;
    std::shared_ptr<IRWerCallback> cb;
public:
    explicit Server();
    virtual ~Server();
    virtual void deleteLater(uint32_t errcode);
    virtual void dump_stat(Dumper dp, void* param) = 0;
    virtual void dump_usage(Dumper dp, void* param) = 0;
};

#ifdef  __cplusplus
extern "C" {
#endif

void releaseall();
void dump_stat();

#ifdef  __cplusplus
}
#endif

bool kill_server(Server* s, uint32_t errcode);
void dump_stat(Dumper dp, void *param);
void dump_usage(Dumper dp, void* param);
#endif
