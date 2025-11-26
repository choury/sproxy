#ifndef FILE_H__
#define FILE_H__

#include "responser.h"

#include <sys/stat.h>
#include <string>

class File: public Responser{
    struct FileStatus{
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
        Range rg;
        uint  flags;
    } status{};

    char filename[URLLIMIT];
    char *suffix = nullptr;
    int  fd = 0;
    struct stat st;
    size_t readHE(Buffer&&);
    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) override;
public:
    explicit File(const char* fname, int fd, const struct stat* st);
    virtual ~File()override;

    virtual void deleteLater(uint32_t error) override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
    static void getfile(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw);
};

void join_arg(std::string& current, const std::string& part);
void join_arg(std::string& current, const std::vector<std::string>& parts);

template <typename... Args>
static std::string pathjoin(const Args&... args) {
    std::string result = "";
    using dummy = int[];
    (void)dummy{ 0, (join_arg(result, args), 0)... };
    return result;
}

std::string resolve(const std::string &path);
std::string make_etag(const struct stat& st);

#endif
