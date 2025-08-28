//
// Created by chouryzhou on 2025/8/25.
//

#ifndef DOH_H
#define DOH_H
// dns over https
#include "responser.h"

class Doh: public Responser{
    struct DohStatus{
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
        std::string                    data; // for storing incoming data in POST requests
    };
    std::map<uint64_t, DohStatus> statusmap;
    size_t succeed_count = 0;
    size_t failed_count = 0;
    static void DnsCB(std::shared_ptr<void>, const char *buff, size_t size);
public:
    Doh();
    virtual ~Doh() override;
    static Doh* GetInstance();

    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif // SPROXY_DOH_H
