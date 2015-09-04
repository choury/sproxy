#ifndef FILE_H__
#define FILE_H__

#include "guest.h"
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

class File:public Peer{
    int ffd = 0;
    size_t leftsize;
    char filename[URLLIMIT];
//protected:
    HttpReqHeader req;
    Range range;
    virtual void openHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events)override;
public:
    File(HttpReqHeader &req, Guest* guest);
    static File *getfile(HttpReqHeader &req, Guest *guest);
    int showerrinfo(int ret, const char *s)override;
};

#endif
