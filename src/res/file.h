#ifndef FILE_H__
#define FILE_H__

#include "responser.h"
#include "prot/http/http_def.h"

#include <sys/stat.h>



class File: public Responser{
    struct FileStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        Range rg;
        uint  flags;
    } status{};

    char filename[URLLIMIT];
    char *suffix = nullptr;
    int  fd = 0;
    struct stat st;
    size_t readHE(Buffer&&);
    virtual void request(std::shared_ptr<HttpReq> req, Requester*) override;
public:
    explicit File(const char* fname, int fd, const struct stat* st);
    virtual ~File()override;

    virtual void deleteLater(uint32_t error) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
    static void getfile(std::shared_ptr<HttpReq> req, Requester* src);
};

#endif
