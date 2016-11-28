#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "parse.h"
#include "object.h"


struct FileStatus{
    Requester* req_ptr;
    uint32_t req_id;
    bool responsed ;
    Range rg;
};



class File:public Responser, public Object{
    void * mapptr = nullptr;
    size_t size;
    char filename[URLLIMIT];
    uint32_t req_id = 1;
    std::map<uint32_t, FileStatus> statusmap;
    bool check(FileStatus& status);
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
