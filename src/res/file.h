#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "prot/http/http_pack.h"

#include <sys/stat.h>


struct FileStatus{
    HttpReq* req;
    HttpRes* res;
    Range rg;
    uint  flags;
};

class File:public Responser{
    char filename[URLLIMIT];
    char *suffix = nullptr;
    int  fd = 0;
    struct stat st;
    FileStatus status;
    virtual void readHE(size_t len);
    virtual void request(HttpReq* req, Requester*) override;
public:
    explicit File(const char* fname, int fd, const struct stat* st);
    virtual ~File()override;

    virtual void dump_stat(Dumper dp, void* param) override;
    static void getfile(HttpReq* req, Requester* src);
};

#endif
