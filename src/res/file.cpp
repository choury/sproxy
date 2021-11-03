#include "file.h"
#include "status.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/config.h"
#include "cgi.h"

#ifdef WITH_GZIP_TEST
#include "gzip_test.h"
#endif

#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <inttypes.h>

using std::vector;
using std::pair;

static std::map<std::string, std::string> mimetype;

static bool checkrange(Range& rg, size_t size) {
    if (rg.begin > (ssize_t)size-1) {
        return false;
    }
    if (rg.begin < 0) {
        if (rg.end == 0) {
            return false;
        }
        rg.begin  = (int)size-rg.end < 0 ? 0 : size-rg.end;
        rg.end = size-1;
    }
    if (rg.end < 0) {
        rg.end = size-1;
    }
    return rg.begin <= rg.end;
}

static std::string pathjoin(const std::string& dirname, const std::string& basename){
    bool endwithslash = endwith(dirname.c_str(), "/");
    bool startwithslash = startwith(basename.c_str(), "/");

    if(endwithslash && startwithslash){
        return dirname + (basename.c_str()+1);
    }else if(endwithslash || startwithslash){
        return dirname + basename;
    }else{
        return dirname +'/'+ basename;
    } 
}

static void loadmine(){
#ifdef __APPLE__
    std::ifstream mimefile("/private/etc/apache2/mime.types");
#else
    std::ifstream mimefile("/etc/mime.types");
#endif
    if(!mimefile.good()){
        LOGE("read /etc/mime.types failed, Content-Type will be disabled.\n");
        return;
    }
    std::string line;
    while(std::getline(mimefile,line)){
        std::stringstream ss(line);
        std::string type;
        if(!(ss>>type)){
            continue;
        }
        if(type.empty() || type[0] == '#'){
            continue;
        }
        std::string suffix;
        while(ss >> suffix){
            mimetype.emplace("." + suffix, type);
        }
    }
    mimefile.close();
}

File::File(const char* fname, int fd, const struct stat* st):fd(fd), st(*st){
    rwer = std::make_shared<FullRWer>([this](int ret, int code){
        LOGE("file error: %d/%d\n", ret, code);
        status.res->trigger(Channel::CHANNEL_ABORT);
        deleteLater(ret);
    });
    if(mimetype.empty()){
        loadmine();
    }
    strcpy(filename, fname);
    memset(&status, 0, sizeof(status));
    suffix = strrchr(filename, '.');
    rwer->SetReadCB(std::bind(&File::readHE, this, _1));
}


void File::request(std::shared_ptr<HttpReq> req, Requester*) {
    status.req = req;
    if (!req->header->ranges.empty()){
        status.rg = req->header->ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
    if(req->header->get("If-Modified-Since")){
        struct tm tp;
        strptime(req->header->get("If-Modified-Since"), "%a, %d %b %Y %H:%M:%S GMT", &tp);
        if(timegm(&tp) >= st.st_mtime){
            HttpResHeader* header = UnpackHttpRes(H304);
            char buff[100];
            strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
            header->set("Last-Modified", buff);
            req->response(std::make_shared<HttpRes>(header, ""));
            return deleteLater(NOERROR);
        }
    }

    if(status.rg.begin == -1 && status.rg.end == -1){
        status.rg.begin = 0;
        status.rg.end = st.st_size - 1;
        HttpResHeader* header = UnpackHttpRes(H200, sizeof(H200));
        header->set("Content-Length", st.st_size);
        char buff[100];
        strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
        header->set("Last-Modified", buff);
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.res = std::make_shared<HttpRes>(header, std::bind(&RWer::EatReadData, rwer));
        req->response(status.res);
    }else if(checkrange(status.rg, st.st_size)){
        HttpResHeader* header = UnpackHttpRes(H206, sizeof(H206));
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes %zd-%zd/%jd",
                 status.rg.begin, status.rg.end, (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        header->set("Content-Length", status.rg.end - status.rg.begin +1);
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.res = std::make_shared<HttpRes>(header, std::bind(&RWer::EatReadData, rwer));
        req->response(status.res);
    }else{
        HttpResHeader* header = UnpackHttpRes(H416, sizeof(H416));
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        req->response(std::make_shared<HttpRes>(header, ""));
        return deleteLater(NOERROR);
    }
    if(status.req->header->ismethod("HEAD")){
        status.res->send((const void*)nullptr, 0);
        status.res->trigger(Channel::CHANNEL_CLOSED);
        return deleteLater(NOERROR);
    }
    req->setHandler([this](Channel::signal s){
        if(s == Channel::CHANNEL_SHUTDOWN){
            status.res->trigger(Channel::CHANNEL_ABORT);
        }
        deleteLater(PEER_LOST_ERR);
    });
}

void File::readHE(buff_block&) {
    if(status.res == nullptr){
        return;
    }
    Range& rg = status.rg;
    LOGD(DFILE, "%s readHE %zd-%zd, flags: %d\n", filename, rg.begin, rg.end, status.flags);
    if (rg.begin > rg.end) {
        status.res->send((const void*)nullptr, 0);
        status.res->trigger(Channel::CHANNEL_CLOSED);
        deleteLater(NOERROR);
        rwer->delEvents(RW_EVENT::READ);
        return;
    }
    int len = Min(status.res->cap(), rg.end - rg.begin + 1);
    if (len <= 0) {
        rwer->delEvents(RW_EVENT::READ);
        return;
    }
    char* buff = (char *)malloc(len);
    len = pread(fd, buff, len, rg.begin);
    if(len <= 0){
        LOGE("file pread error: %s\n", strerror(errno));
        free(buff);
        status.res->trigger(Channel::CHANNEL_ABORT);
        deleteLater(SOCKET_ERR);
        rwer->delEvents(RW_EVENT::READ);
        return;
    }
    status.res->send(buff, len);
    rg.begin += len;
    free(buff);
}

void File::deleteLater(uint32_t error) {
    status.req = nullptr;
    Server::deleteLater(error);
}

void File::dump_stat(Dumper dp, void* param){
    dp(param, "File %p, %s\n", this, filename);
    dp(param, " [%" PRIu32 "]: (%zd-%zd)\n",
            status.req->header->request_id, status.rg.begin, status.rg.end);
}

File::~File() {
    if(fd > 0){
        close(fd);
    }
}

void File::getfile(std::shared_ptr<HttpReq> req, Requester* src) {
    if(!req->header->getrange()){
        return req->response(std::make_shared<HttpRes>(UnpackHttpRes(H400), ""));
    }
    char filename[URLLIMIT];
    bool slash_end = req->header->filename.back() == '/';
    bool index_not_found = false;
    (void)realpath(("./" + req->header->filename).c_str(), filename);
    HttpResHeader* header = nullptr;
    while(true){
        if(!startwith(filename, opt.rootdir)){
            LOGE("get file out of rootdir: %s\n", filename);
            header = UnpackHttpRes(H403, sizeof(H403));
            goto ret;
        }
        if(filename == pathjoin(opt.rootdir, "status")){
            return (new Status())->request(req, src);
        }
#ifdef WITH_GZIP_TEST
        if(filename == pathjoin(opt.rootdir, "test")){
            return (new GzipTest())->request(req, src);
        }
#endif
        char *suffix = strrchr(filename, '.');
        if(suffix && strcmp(suffix, ".do") == 0){
#if __APPLE__
            strcpy(suffix, ".dylib");
#elif __linux__
            strcpy(suffix, ".so");
#endif
        }
        struct stat st;
        if(stat(filename, &st) < 0){
            LOGE("get file stat failed %s: %s\n", filename, strerror(errno));
            if(errno == ENOENT){
                // filname is index file now, fallback to autoindex
                if(slash_end && !endwith(filename, "/") && opt.autoindex){
                    index_not_found = true;
                    (void)realpath(("./" + req->header->filename).c_str(), filename);
                    continue;
                }
                header = UnpackHttpRes(H404, sizeof(H404));
            }else{
                header = UnpackHttpRes(H500, sizeof(H500));
            }
            goto ret;
        }

        if(S_ISDIR(st.st_mode)){
            if(!slash_end){
                header = UnpackHttpRes(H302, sizeof(H302));
                char location[FILENAME_MAX];
                snprintf(location, sizeof(location), "/%s/", req->header->filename.c_str());
                header->set("Location", location);
                goto ret;
            }
            if(!index_not_found && opt.index_file){
                (void)realpath(("./" + req->header->filename + opt.index_file).c_str(), filename);
                continue;
            }
            if(!opt.autoindex){
                header = UnpackHttpRes(H403, sizeof(H403));
                goto ret;
            }

            DIR* dir = opendir(filename);
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", filename, strerror(errno));
                header = UnpackHttpRes(H500, sizeof(H500));
                goto ret;
            }
            header = UnpackHttpRes(H200, sizeof(H200));
            header->set("Transfer-Encoding", "chunked");
            auto res = std::make_shared<HttpRes>(header);
            req->response(res);
            char buff[1024];
            res->send((const void*)buff,
                    sprintf(buff, "<html>"
                                  "<head><title>Index of %s</title></head>"
                                  "<body><h1>Index of %s</h1><hr/><pre>",
                                  req->header->filename.c_str(),
                                  req->header->filename.c_str()));
            struct dirent *ptr;
            while((ptr = readdir(dir))){
                if(ptr->d_type == DT_DIR){
                    res->send((const void*)buff,
                                   sprintf(buff, "<a href='%s/'>%s/</a><br/>", ptr->d_name, ptr->d_name));
                }else{
                    res->send((const void*)buff,
                                   sprintf(buff, "<a href='%s'>%s</a><br/>", ptr->d_name, ptr->d_name));

                }
            }
            closedir(dir);
            res->send((const void*)buff, sprintf(buff, "</pre><hr></body></html>"));
            res->send((const void*)nullptr, 0);
            res->trigger(Channel::CHANNEL_CLOSED);
            return;
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", filename);
            header = UnpackHttpRes(H403, sizeof(H403));
            goto ret;
        }
#if __APPLE__
        if(suffix && strcmp(suffix, ".dylib") == 0){
#elif __linux__
        if(suffix && strcmp(suffix, ".so") == 0){
#else
        if(0){
#endif
            return getcgi(req, filename, src);
        }
        int fd = open(filename, O_RDONLY | O_CLOEXEC);
        if(fd < 0){
            LOGE("open file failed %s: %s\n", filename, strerror(errno));
            header = UnpackHttpRes(H500, sizeof(H500));
            goto ret;
        }
        return (new File(filename, fd, &st))->request(req, src);
    }
ret:
    assert(header);
    return req->response(std::make_shared<HttpRes>(header, ""));
}
