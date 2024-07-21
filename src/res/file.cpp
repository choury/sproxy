#include "file.h"
#include "status.h"
#include "rproxy.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/config.h"
#include "cgi.h"

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

#ifdef __linux__
#define LIBSUFFIX ".so"
#endif
#ifdef __APPLE__
#define LIBSUFFIX ".dylib"
#endif


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

template <class... T>
static std::string pathjoin(const std::string&a, const std::string& b, const T&... left){
    return pathjoin(a, pathjoin(b, left...));
}

// pathjoin for vector, 返回绝对路径
static std::string pathjoin(const std::vector<std::string>& path){
    std::string ret = "/";
    for(auto& p : path){
        ret = pathjoin(ret, p);
    }
    return ret;
}

static std::string absolute(const std::string &path) {
    // 获取当前工作目录
    char current_dir[PATH_MAX];
    if (getcwd(current_dir, sizeof(current_dir)) == nullptr) {
        LOGE("error getting current working directory %s\n", strerror(errno));
        return "";
    }
    std::string input_path = std::string(current_dir) + '/' + path;

    std::vector<std::string> path_parts;
    std::istringstream iss(input_path);
    std::string part;
    while (std::getline(iss, part, '/')) {
        if (part == "..") {
            if (!path_parts.empty()) {
                path_parts.pop_back();
            }
        } else if (!part.empty() && part != ".") {
            path_parts.push_back(part);
        }
    }

    return pathjoin(path_parts);
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
        status.res->send(CHANNEL_ABORT);
        deleteLater(ret);
    });
    if(mimetype.empty()){
        loadmine();
    }
    strcpy(filename, fname);
    suffix = strrchr(filename, '.');
    rwer->SetReadCB([this](Buffer&& bb){return readHE(std::move(bb));});
}

File::~File() {
    status.req = nullptr;
    if(fd > 0){
        close(fd);
    }
}

void File::request(std::shared_ptr<HttpReq> req, Requester*) {
    status.req = req;
    if (!req->header->ranges.empty()){
        status.rg = req->header->ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
    uint64_t id = req->header->request_id;
    if(req->header->get("If-Modified-Since")){
        struct tm tp;
        strptime(req->header->get("If-Modified-Since"), "%a, %d %b %Y %H:%M:%S GMT", &tp);
        if(timegm(&tp) >= st.st_mtime){
            std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S304, sizeof(S304), id);
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
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S200, sizeof(S200), id);
        header->set("Content-Length", st.st_size);
        char buff[100];
        strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
        header->set("Last-Modified", buff);
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.res = std::make_shared<HttpRes>(header, [this]{ rwer->Unblock(0);});
        req->response(status.res);
    }else if(checkrange(status.rg, st.st_size)){
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S206, sizeof(S206), id);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes %zd-%zd/%jd",
                 status.rg.begin, status.rg.end, (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        header->set("Content-Length", status.rg.end - status.rg.begin +1);
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.res = std::make_shared<HttpRes>(header, [this]{ rwer->Unblock(0);});
        req->response(status.res);
    }else{
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S416, sizeof(S416), id);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        req->response(std::make_shared<HttpRes>(header, ""));
        return deleteLater(NOERROR);
    }
    if(status.req->header->ismethod("HEAD")){
        status.res->send(Buffer{nullptr, req->header->request_id});
        return deleteLater(NOERROR);
    }
    req->attach([this](ChannelMessage&& msg){
        if(msg.type != ChannelMessage::CHANNEL_MSG_SIGNAL){
            return 1;
        }
        deleteLater(PEER_LOST_ERR);
        return 0;
    }, []{return 0;});
}

size_t File::readHE(Buffer&& bb) {
    if(status.res == nullptr){
        return 0;
    }
    Range& rg = status.rg;
    LOGD(DFILE, "%s readHE %zd-%zd, flags: %d\n", filename, rg.begin, rg.end, status.flags);
    if (rg.begin > rg.end) {
        status.res->send(Buffer{nullptr, bb.id});
        deleteLater(NOERROR);
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    int len = std::min((long)status.res->cap(), rg.end - rg.begin + 1l);
    if (len <= 0) {
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    Block buff(len);
    len = pread(fd, buff.data(), len, rg.begin);
    if(len <= 0){
        LOGE("file pread error: %s\n", strerror(errno));
        status.res->send(CHANNEL_ABORT);
        deleteLater(SOCKET_ERR);
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    status.res->send({std::move(buff), (size_t)len, bb.id});
    rg.begin += len;
    return 0;
}

void File::deleteLater(uint32_t error) {
    status.req->detach();
    Server::deleteLater(error);
}

void File::dump_stat(Dumper dp, void* param){
    dp(param, "File %p, %s, fd=%d\n", this, filename, fd);
    dp(param, "  [%" PRIu64 "]: (%zd-%zd), flags: 0x%08x\n",
            status.req->header->request_id,
            status.rg.begin, status.rg.end, status.flags);
}

void File::dump_usage(Dumper dp, void *param) {
    if(status.res) {
        dp(param, "File %p: %zd, res: %zd\n", this, sizeof(*this), status.res->mem_usage());
    } else {
        dp(param, "File %p: %zd\n", this, sizeof(*this));
    }
}


void File::getfile(std::shared_ptr<HttpReq> req, Requester* src) {
    uint64_t id = req->header->request_id;
    if(!req->header->getrange()){
        return req->response(std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id), ""));
    }
    char filename[URLLIMIT];
    bool slash_end = req->header->filename.back() == '/';
    bool index_not_found = false;
    snprintf(filename, sizeof(filename), "%s", absolute(req->header->filename).c_str());
    std::shared_ptr<HttpResHeader> header = nullptr;
    while(true){
        if(!startwith(filename, opt.rootdir)){
            LOGE("get file out of rootdir: %s\n", filename);
            header = HttpResHeader::create(S403, sizeof(S403), id);
            goto ret;
        }
        if(filename == pathjoin(opt.rootdir, "status")){
            return (new Status())->request(req, src);
        }
        if(startwith(filename, pathjoin(opt.rootdir, "rproxy/").c_str())) {
            return RproxyRequest(req, src);
        }
        if(filename == pathjoin(opt.rootdir, "test")){
            //for compatibility
            strcpy(filename, pathjoin(opt.rootdir, "cgi/libtest.do").c_str());
        }
        char *suffix = strrchr(filename, '.');
        if(suffix && strcmp(suffix, ".do") == 0){
            strcpy(suffix, LIBSUFFIX);
        }
        struct stat st;
        if(stat(filename, &st) < 0){
            LOGE("get file stat failed %s: %s\n", filename, strerror(errno));
            if(errno == ENOENT){
                // filname is index file now, fallback to autoindex
                if(slash_end && !endwith(filename, "/") && opt.autoindex){
                    index_not_found = true;
                    //(void)!realpath(("./" + req->header->filename).c_str(), filename);
                    snprintf(filename, sizeof(filename), "%s", absolute(req->header->filename).c_str());
                    continue;
                }
                header = HttpResHeader::create(S404, sizeof(S404), id);
            }else{
                header = HttpResHeader::create(S500, sizeof(S500), id);
            }
            goto ret;
        }

        if(S_ISDIR(st.st_mode)){
            if(!slash_end){
                header = HttpResHeader::create(S302, sizeof(S302), id);
                char location[URLLIMIT];
                snprintf(location, sizeof(location), "/%s/", req->header->filename.c_str());
                header->set("Location", location);
                goto ret;
            }
            if(!index_not_found && opt.index_file){
                //(void)!realpath(("./" + req->header->filename + opt.index_file).c_str(), filename);
                snprintf(filename, sizeof(filename), "%s", absolute(req->header->filename + opt.index_file).c_str());
                continue;
            }
            if(!opt.autoindex){
                header = HttpResHeader::create(S403, sizeof(S403), id);
                goto ret;
            }

            DIR* dir = opendir(filename);
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", filename, strerror(errno));
                header = HttpResHeader::create(S500, sizeof(S500), id);
                goto ret;
            }
            header = HttpResHeader::create(S200, sizeof(S200), id);
            header->set("Transfer-Encoding", "chunked");
            auto res = std::make_shared<HttpRes>(header);
            req->response(res);
            char buff[1024];
            res->send({buff,(size_t)snprintf(buff, sizeof(buff),
                            "<html>"
                            "<head><title>Index of %s</title></head>"
                            "<body><h1>Index of %s</h1><hr/><pre>",
                            req->header->filename.c_str(),
                            req->header->filename.c_str()), id});
            struct dirent *ptr;
            while((ptr = readdir(dir))){
                if(ptr->d_type == DT_DIR){
                    res->send({buff,
                              (size_t)snprintf(buff, sizeof(buff), "<a href='%s/'>%s/</a><br/>", ptr->d_name, ptr->d_name),
                              id});
                }else{
                    res->send({buff,
                               (size_t)snprintf(buff, sizeof(buff), "<a href='%s'>%s</a><br/>", ptr->d_name, ptr->d_name),
                               id});
                }
            }
            closedir(dir);
            res->send({buff, (size_t)snprintf(buff, sizeof(buff), "</pre><hr></body></html>"), id});
            res->send(Buffer{nullptr, id});
            return;
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", filename);
            header = HttpResHeader::create(S403, sizeof(S403), id);
            goto ret;
        }
        if(suffix && strcmp(suffix, LIBSUFFIX) == 0){
            return getcgi(req, filename, src);
        }
        int fd = open(filename, O_RDONLY | O_CLOEXEC);
        if(fd < 0){
            LOGE("open file failed %s: %s\n", filename, strerror(errno));
            header = HttpResHeader::create(S500, sizeof(S500), id);
            goto ret;
        }
        return (new File(filename, fd, &st))->request(req, src);
    }
ret:
    assert(header);
    return req->response(std::make_shared<HttpRes>(header, ""));
}
