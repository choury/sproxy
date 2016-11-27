#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "parse.h"
#include "object.h"

struct range{
    ssize_t begin;
    ssize_t end;
};

struct FileStatus{
    HttpReqHeader req;
    range rg;
};

class Ranges{
    void add(ssize_t begin, ssize_t end);
public:
    std::vector<range> rgs;
    Ranges(const char *range_str);
    size_t size();
    bool calcu(size_t size);
};

class File:public Responser, public Object{
    void * mapptr = nullptr;
    size_t size;
    char filename[URLLIMIT];
    uint32_t req_id = 1;
    std::map<uint32_t, FileStatus> statusmap;
    virtual void defaultHE(uint32_t events);
    virtual uint32_t request(HttpReqHeader&& req) override;
public:
    File(HttpReqHeader& req);
    ~File();
    virtual void clean(uint32_t errcode, uint32_t id)override;
    static File* getfile(HttpReqHeader& req);
};

#endif
