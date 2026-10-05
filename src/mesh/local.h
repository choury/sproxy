#ifndef MESH_LOCAL_H__
#define MESH_LOCAL_H__

#include "res/responser.h"

#include <map>

// /mesh/* 控制面端点，仿 Doh 的单例 Responser：
// GET 端点直接应答，POST /mesh/announce 需消费请求体后交 MeshManager 合并
class MeshLocal: public Responser {
    struct AnnStatus {
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>      rw;
        std::shared_ptr<IRWerCallback> cb;
        std::string                   data;
    };
    std::map<uint64_t, AnnStatus> statusmap;
    uint64_t succeed_count = 0;
    uint64_t failed_count = 0;

    void announce(uint64_t id);
public:
    MeshLocal();
    virtual ~MeshLocal() override;
    static MeshLocal* GetInstance();

    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

#endif
