#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "parse.h"
#include <vector>

class Range{
    void add(ssize_t begin,ssize_t end);
public:
    std::vector<std::pair<ssize_t,ssize_t>> ranges;
    Range(const char *range);
    size_t size();
    bool calcu(size_t size);
};

class File:public Responser{
    void * mapptr = nullptr;
    size_t offset = 0;
    size_t size;
    char filename[URLLIMIT];
    std::queue<HttpReqHeader> reqs;
    virtual void openHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
public:
    File(const char *fname);
    ~File();
    virtual int showerrinfo(int ret, const char *s)override;
    virtual Ptr request(HttpReqHeader &req) override;
};

#endif
