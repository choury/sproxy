#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "parse.h"
#include <list>

struct range{
    ssize_t begin;
    ssize_t end;
};

class Ranges{
    void add(ssize_t begin, ssize_t end);
public:
    std::vector<range> rgs;
    Ranges(const char *range_str);
    size_t size();
    bool calcu(size_t size);
};

class File:public Responser{
    void * mapptr = nullptr;
    size_t size;
    char filename[URLLIMIT];
    std::list<std::pair<HttpReqHeader,range>> reqs;
    virtual void defaultHE(uint32_t events);
public:
    File(HttpReqHeader& req);
    ~File();
    virtual int showerrinfo(int ret, const char *s)override;
    virtual Ptr request(HttpReqHeader &req) override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    static Ptr getfile(HttpReqHeader &req);
};

#endif
