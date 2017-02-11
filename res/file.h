#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "prot/parse.h"

#include <sys/stat.h>


struct FileStatus{
    Requester* req_ptr;
    uint32_t req_id;
    bool responsed;
    bool head_only;
    time_t modified_since;
    Range rg;
};



class File:public Responser{
    char filename[URLLIMIT];
    char *suffix = nullptr;
    int  ffd = 0;
    struct stat st;
    bool valid = true;
    uint32_t req_id = 1;
    std::map<uint32_t, FileStatus> statusmap;
    bool checkvalid();
    virtual void defaultHE(uint32_t events);
    virtual uint32_t request(HttpReqHeader&& req) override;
public:
    explicit File(HttpReqHeader& req);
    ~File();
    virtual void clean(uint32_t errcode, uint32_t id)override;
    static File* getfile(HttpReqHeader& req);
};

bool checkrange(Range& rg, size_t size);

#endif
