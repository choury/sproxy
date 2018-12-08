#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "prot/http_pack.h"

#include <sys/stat.h>


struct FileStatus{
    std::weak_ptr<Requester> req_ptr;
    void*      req_index;
    bool responsed;
    bool head_only;
    time_t modified_since;
    Range rg;
};



class File:public Responser{
    char filename[URLLIMIT];
    char *suffix = nullptr;
    int  fd = 0;
    struct stat st;
    bool valid = true;
    uint32_t req_id = 1;
    std::map<uint32_t, FileStatus> statusmap;
    bool checkvalid();
    void evictMe();
    virtual void readHE(size_t len);
    virtual void deleteLater(uint32_t errcode) override;
    virtual void* request(HttpReqHeader* req) override;
public:
    explicit File(const char* fname, int fd, const struct stat* st);
    ~File();
    virtual int32_t bufleft(void* index)override;
    virtual void Send(const void* buff, size_t size, void* index)override;

    virtual void finish(uint32_t flags, void* index)override;
    virtual void dump_stat(Dumper dp, void* param) override;
    static std::weak_ptr<Responser> getfile(HttpReqHeader* req);
};

#endif
