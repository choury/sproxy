#include "file.h"
#include "status.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/memio.h"
#include "cgi.h"
#include "doh.h"

#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

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

std::string make_etag(const struct stat& st) {
    unsigned long nsec = 0;
#if defined(__APPLE__)
    nsec = static_cast<unsigned long>(st.st_mtimespec.tv_nsec);
#elif defined(st_mtime) || defined(__linux__)
    nsec = static_cast<unsigned long>(st.st_mtim.tv_nsec);
#endif
    char etag[80];
    if (nsec != 0) {
        snprintf(etag, sizeof(etag), "\"%lx-%lx-%lx\"", (unsigned long)st.st_ino, (unsigned long)st.st_mtime, nsec);
    } else {
        snprintf(etag, sizeof(etag), "\"%lx-%lx\"", (unsigned long)st.st_ino, (unsigned long)st.st_mtime);
    }
    return etag;
}

static bool match_etag_list(const char* header, const std::string& etag) {
    if (header == nullptr) {
        return false;
    }
    std::string list(header);
    size_t pos = 0;
    while (pos < list.size()) {
        size_t comma = list.find(',', pos);
        std::string token = comma == std::string::npos ? list.substr(pos) : list.substr(pos, comma - pos);
        size_t start = 0;
        while (start < token.size() && (token[start] == ' ' || token[start] == '\t')) {
            start++;
        }
        size_t end = token.size();
        while (end > start && (token[end - 1] == ' ' || token[end - 1] == '\t')) {
            end--;
        }
        token = token.substr(start, end - start);
        if (token == "*" || token == etag) {
            return true;
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

static std::string join_one(const std::string& dirname, const std::string& basename){
    if (dirname.empty()) return basename;
    bool endwithslash = endwith(dirname.c_str(), "/");
    bool startwithslash = startwith(basename.c_str(), "/");

    if(endwithslash && startwithslash){
        return dirname + (basename.c_str()+1);
    }
    if(endwithslash || startwithslash){
        return dirname + basename;
    }
    return dirname +'/'+ basename;
}

void join_arg(std::string& current, const std::string& part) {
    if (current.empty()) {
        current = part;
    } else {
        current = join_one(current, part);
    }
}

void join_arg(std::string& current, const std::vector<std::string>& parts) {
    for (const auto& p : parts) {
        join_arg(current, p); // 递归调用 string 版本
    }
}

//返回一个解析过的相对路径
std::string resolve(const std::string &path) {
    std::vector<std::string> path_parts;
    std::istringstream iss(path);
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
    cb = IRWerCallback::create()->onRead([this](Buffer&& bb){
        return readHE(std::move(bb));
    })->onError([this](int ret, int code){
        LOGE("file error: %d/%d\n", ret, code);
        deleteLater(ret);
    });
    rwer = std::make_shared<FullRWer>(cb);
    if(mimetype.empty()){
        loadmine();
    }
    strcpy(filename, fname);
    suffix = strrchr(filename, '.');
}

File::~File() {
    status.req = nullptr;
    if(fd > 0){
        close(fd);
    }
}

void File::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    status.req = req;
    status.rw = rw;
    if (!req->ranges.empty()){
        status.rg = req->ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
    uint64_t id = req->request_id;
    const std::string etag = make_etag(st);
    const char* if_match = req->get("If-Match");
    if (if_match && !match_etag_list(if_match, etag)) {
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S412, sizeof(S412), id);
        header->set("ETag", etag);
        response(rw, header, "");
        return deleteLater(NOERROR);
    }

    const char* if_none_match = req->get("If-None-Match");
    if (if_none_match && match_etag_list(if_none_match, etag)) {
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S304, sizeof(S304), id);
        char buff[100];
        strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
        header->set("Last-Modified", buff);
        header->set("ETag", etag);
        response(rw, header);
        return deleteLater(NOERROR);
    }

    const char* if_modified_since = req->get("If-Modified-Since");
    if(!if_none_match && if_modified_since){
        struct tm tp;
        strptime(if_modified_since, "%a, %d %b %Y %H:%M:%S GMT", &tp);
        if(timegm(&tp) >= st.st_mtime){
            std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S304, sizeof(S304), id);
            char buff[100];
            strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
            header->set("Last-Modified", buff);
            header->set("ETag", etag);
            response(rw, header);
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
        header->set("ETag", etag);
        header->set("Cache-Control", "no-cache");
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.rw->SendHeader(header);
    }else if(checkrange(status.rg, st.st_size)){
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S206, sizeof(S206), id);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes %zd-%zd/%jd",
                 status.rg.begin, status.rg.end, (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        header->set("Content-Length", status.rg.end - status.rg.begin +1);
        header->set("ETag", etag);
        header->set("Cache-Control", "no-cache");
        if(suffix && mimetype.count(suffix)){
            header->set("Content-Type", mimetype.at(suffix));
        }
        status.rw->SendHeader(header);
    }else{
        std::shared_ptr<HttpResHeader> header = HttpResHeader::create(S416, sizeof(S416), id);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
        header->set("Content-Range", buff);
        response(rw, header, "");
        return deleteLater(NOERROR);
    }
    if(status.req->ismethod("HEAD")){
        status.rw->Send(Buffer{nullptr, req->request_id});
        return deleteLater(NOERROR);
    }
    status.cb = IRWerCallback::create()->onError([this](int, int){
        deleteLater(PEER_LOST_ERR);
    });
    status.rw->SetCallback(status.cb);
}

size_t File::readHE(Buffer&& bb) {
    if(status.rw == nullptr){
        return 0;
    }
    Range& rg = status.rg;
    LOGD(DFILE, "%s readHE %zd-%zd, flags: %d\n", filename, rg.begin, rg.end, status.flags);
    if (rg.begin > rg.end) {
        status.rw->Send(Buffer{nullptr, bb.id});
        deleteLater(NOERROR);
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    int len = std::min({(long)status.rw->cap(bb.id), rg.end - rg.begin + 1l, (long)BUF_LEN});
    if (len <= 0) {
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    Block buff(len);
    len = pread(fd, buff.data(), len, rg.begin);
    if(len <= 0){
        LOGE("file pread error: %s\n", strerror(errno));
        deleteLater(SOCKET_ERR);
        rwer->delEvents(RW_EVENT::READ);
        return 0;
    }
    status.rw->Send({std::move(buff), (size_t)len, bb.id});
    rg.begin += len;
    return 0;
}

void File::deleteLater(uint32_t error) {
    if(status.rw){
        status.rw->SetCallback(nullptr);
        status.rw->Close();
        status.rw = nullptr;
    }
    Server::deleteLater(error);
}

void File::dump_stat(Dumper dp, void* param){
    dp(param, "File %p, %s, fd=%d\n", this, filename, fd);
    dp(param, "  [%" PRIu64 "]: (%zd-%zd), flags: 0x%08x\n",
            status.req->request_id,
            status.rg.begin, status.rg.end, status.flags);
}

void File::dump_usage(Dumper dp, void *param) {
    if(status.rw) {
        dp(param, "File %p: %zd, res: %zd\n", this, sizeof(*this), status.rw->mem_usage());
    } else {
        dp(param, "File %p: %zd\n", this, sizeof(*this));
    }
}


void File::getfile(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    uint64_t id = req->request_id;
    std::string filename = resolve(req->filename);
    bool is_webdav = false;
    if(filename == "status"){
        return (new Status())->request(req, rw);
    }else if (filename == "dns-query"){
        return Doh::GetInstance()->request(req, rw);
    }else if(filename == "rproxy/sw") {
        filename = "webui/sw.html";
    }else if(filename == "rproxy/sw.js") {
        filename = "webui/sw.js";
    }else if(filename == "rproxy" || startwith(filename.c_str(), "rproxy/")) {
        return distribute_rproxy(req, rw);
    }else if(filename == "test"){
        //for compatibility
        std::string cgi = pathjoin(opt.rootdir, std::string("cgi/libtest") + LIBSUFFIX);
        return getcgi(req, cgi.c_str(), rw);
    }else if(opt.webdav_root && (req->ismethod("GET") || req->ismethod("HEAD")) && startwith(filename.c_str(), "webdav/")){
        if(!checkauth(rw->getSrc().hostname, req->get("Authorization"), req->get("Proxy-Authorization"))) {
            auto sheader = HttpResHeader::create(S401, sizeof(S401), id);
            sheader->set("WWW-Authenticate", "Basic realm=\"Secure Area\"");
            return response(rw, sheader, "");
        }
        is_webdav = true;
        //strip "/webdav/"
        filename = resolve(req->filename.substr(7));
    }else if(opt.webdav_root && (filename == "webdav" || startwith(filename.c_str(), "webdav/"))){
        std::string cgi = pathjoin(opt.rootdir, std::string("cgi/libwebdav") + LIBSUFFIX);
        return getcgi(req, cgi.c_str(), rw);
    }else if(opt.acme_state && startwith(filename.c_str(), ".well-known/acme-challenge/")) {
        std::string cgi = pathjoin(opt.rootdir, std::string("cgi/libacme") + LIBSUFFIX);
        return getcgi(req, cgi.c_str(), rw);
    }
    if(!req->getrange()){
        return response(rw, HttpResHeader::create(S400, sizeof(S400), id), "");
    }
    bool slash_end = req->filename.back() == '/';
    bool index_not_found = false;
    std::shared_ptr<HttpResHeader> header = nullptr;
    while(true){
        size_t pos = filename.rfind('.');
        std::string suffix = (pos == std::string::npos) ? "":filename.substr(pos);
        if (suffix == ".do" && !is_webdav) {
            filename = filename.substr(0, pos) + LIBSUFFIX;
            suffix = LIBSUFFIX;
        }
        std::string path = pathjoin(is_webdav ? opt.webdav_root: opt.rootdir, filename);
        struct stat st;
        if(stat(path.c_str(), &st) < 0){
            LOGE("get file stat failed %s: %s\n", path.c_str(), strerror(errno));
            if(errno == ENOENT){
                // filname is index file now, fallback to autoindex
                if(slash_end && !endwith(path.c_str(), "/") && opt.autoindex){
                    index_not_found = true;
                    //(void)!realpath(("./" + req->header->filename).c_str(), filename);
                    filename = resolve(req->filename);
                    continue;
                }
                header = HttpResHeader::create(S404, sizeof(S404), id);
            }else{
                header = HttpResHeader::create(S500, sizeof(S500), id);
            }
            goto ret;
        }

        if(S_ISDIR(st.st_mode)){
            if(!index_not_found && opt.index_file){
                //(void)!realpath(("./" + req->header->filename + opt.index_file).c_str(), filename);
                filename = resolve(req->filename + "/" + opt.index_file);
                continue;
            }
            if(!opt.autoindex){
                header = HttpResHeader::create(S403, sizeof(S403), id);
                goto ret;
            }

            DIR* dir = opendir(path.c_str());
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", path.c_str(), strerror(errno));
                header = HttpResHeader::create(S500, sizeof(S500), id);
                goto ret;
            }
            header = HttpResHeader::create(S200, sizeof(S200), id);
            header->set("Transfer-Encoding", "chunked");
            rw->SendHeader(header);
            char buff[2048];
            rw->Send({buff,(size_t)snprintf(buff, sizeof(buff),
                            "<html>"
                            "<head><title>Index of %s</title></head>"
                            "<body><h1>Index of %s</h1><hr/><pre>"
                            "<a href='../'>../</a><br/>",
                            filename.c_str(),
                            filename.c_str()), id});
            struct dirent *ptr;
            std::set<std::string> dirs;
            std::set<std::string> files;
            while((ptr = readdir(dir))){
                if(strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0){
                    continue;
                }
                if(ptr->d_type == DT_DIR){
                    dirs.emplace(ptr->d_name);
                }else{
                    files.emplace(ptr->d_name);
                }
            }
            closedir(dir);
            char name[1024];
            for(const auto& dir: dirs) {
                URLEncode(name, dir.c_str(), dir.length());
                rw->Send({buff, (size_t)snprintf(buff, sizeof(buff), "<a href='%s/'>%s/</a><br/>", name, dir.c_str()), id});
            }
            for(const auto& file: files) {
                URLEncode(name, file.c_str(), file.length());
                rw->Send({buff, (size_t)snprintf(buff, sizeof(buff), "<a href='%s'>%s</a><br/>", name, file.c_str()), id});
            }
            rw->Send({buff, (size_t)snprintf(buff, sizeof(buff), "</pre><hr></body></html>"), id});
            rw->Send(Buffer{nullptr, id});
            return;
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", path.c_str());
            header = HttpResHeader::create(S403, sizeof(S403), id);
            goto ret;
        }
        if(suffix == LIBSUFFIX && !is_webdav){
            return getcgi(req, path.c_str(), rw);
        }
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if(fd < 0){
            LOGE("open file failed %s: %s\n", path.c_str(), strerror(errno));
            header = HttpResHeader::create(S500, sizeof(S500), id);
            goto ret;
        }
        return (new File(path.c_str(), fd, &st))->request(req, rw);
    }
ret:
    assert(header);
    return response(rw, header, "");
}
