#include "file.h"
#include "status.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/net.h"
#include "misc/util.h"
#include "misc/config.h"

#ifdef ENABLE_GZIP_TEST
#include "gzip_test.h"
#endif
#ifdef ENABLE_CGI
#include "cgi.h"
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


using std::vector;
using std::pair;


static std::map<std::string, std::weak_ptr<File>> filemap;
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
    rwer = new EventRWer([this](int ret, int code){
        LOGE("file error: %d/%d\n", ret, code);
        deleteLater(ret);
    });
    if(filemap.empty()){
        loadmine();
    }
    strcpy(filename, fname);
    filemap[filename] = std::dynamic_pointer_cast<File>(shared_from_this());
    suffix = strrchr(filename, '.');
    rwer->SetReadCB(std::bind(&File::readHE, this, _1));
}


bool File::checkvalid() {
    struct stat nt;
    if(stat(filename, &nt)){
        valid = false;
    }else{
        valid = nt.st_mtime == st.st_mtime && nt.st_ino == st.st_ino;
    }
    if(!valid){
        evictMe();
        rwer->addEvents(RW_EVENT::READ);
    }
    return valid;
}

void File::evictMe(){
    if(filemap.count(filename) == 0){
        return;
    }
    if(!filemap[filename].expired() && filemap[filename].lock() != shared_from_this()){
        return;
    }
    filemap.erase(filename);
}

int32_t File::bufleft(void*){
    return 0;
}

//discard everything!
void File::Send(const void*, size_t, void*) {
}

void* File::request(HttpReqHeader* req) {
    FileStatus status;
    status.req_ptr = req->src;
    status.req_index = req->index;
    status.head_only = req->ismethod("HEAD");
    status.responsed = false;
    if (!req->ranges.empty()){
        status.rg = req->ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
    if(req->get("If-Modified-Since")){
        struct tm tp;
        strptime(req->get("If-Modified-Since"), "%a, %d %b %Y %H:%M:%S GMT", &tp);
        status.modified_since = timegm(&tp);
    }else{
        status.modified_since = 0;
    }
    statusmap[req_id] = status;
    delete req;
    rwer->addEvents(RW_EVENT::READ);
    rwer->buffer_insert(rwer->buffer_end(), write_block{p_strdup("FILEFILE"), 8, 0});
    return reinterpret_cast<void*>(req_id++);
}


void File::readHE(size_t len) {
    rwer->consume(nullptr, len);
    rwer->buffer_insert(rwer->buffer_end(), write_block{p_strdup("FILEFILE"), 8, 0});

    bool allfull = true;
    for(auto i = statusmap.begin();i!=statusmap.end();){
        Range& rg = i->second.rg;
        assert(!i->second.req_ptr.expired());
        auto requester = i->second.req_ptr.lock();
        if (!i->second.responsed){
            if(i->second.modified_since >= st.st_mtime){
                HttpResHeader* res = new HttpResHeader(H304, sizeof(H304));
                char buff[100];
                strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
                res->set("Last-Modified", buff);
                res->index = i->second.req_index;
                requester->response(res);
                requester->finish(NOERROR | DISCONNECT_FLAG, i->second.req_index);
                i = statusmap.erase(i);
                continue;
            }
            if(rg.begin == -1 && rg.end == -1){
                rg.begin = 0;
                rg.end = st.st_size - 1;
                HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
                res->set("Content-Length", st.st_size);
                char buff[100];
                strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
                res->set("Last-Modified", buff);
                if(suffix && mimetype.count(suffix)){
                    res->set("Content-Type", mimetype.at(suffix));
                }
                res->index = i->second.req_index;
                requester->response(res);
            }else if(checkrange(rg, st.st_size)){
                HttpResHeader* res = new HttpResHeader(H206, sizeof(H206));
                char buff[100];
                snprintf(buff, sizeof(buff), "bytes %zd-%zd/%jd",
                         rg.begin, rg.end, (intmax_t)st.st_size);
                res->set("Content-Range", buff);
                size_t leftsize = rg.end - rg.begin+1;
                res->set("Content-Length", leftsize);
                if(suffix && mimetype.count(suffix)){
                    res->set("Content-Type", mimetype.at(suffix));
                }
                res->index = i->second.req_index;
                requester->response(res);
            }else{
                HttpResHeader* res = new HttpResHeader(H416, sizeof(H416));
                char buff[100];
                snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
                res->set("Content-Range", buff);
                res->index = i->second.req_index;
                requester->response(res);
                requester->finish(NOERROR | DISCONNECT_FLAG, i->second.req_index);
                i = statusmap.erase(i);
                continue;
            }
            if(i->second.head_only){
                requester->finish(NOERROR | DISCONNECT_FLAG, i->second.req_index);
                i = statusmap.erase(i);
                continue;
            }else{
                i->second.responsed = true;
            }
        }
        if (rg.begin > rg.end) {
            requester->finish(NOERROR | DISCONNECT_FLAG, i->second.req_index);
            i = statusmap.erase(i);
            continue;
        }
        int len = Min(requester->bufleft(i->second.req_index), rg.end - rg.begin + 1);
        if (len <= 0) {
            i++;
            continue;
        }
        allfull = false;
        char* const buff = (char *)p_malloc(len);
        len = pread(fd, buff, len, rg.begin);
        if(len <= 0){
            LOGE("file pread error: %s\n", strerror(errno));
            deleteLater(READ_ERR);
            return;
        }
        requester->Send(buff, len, i->second.req_index);
        rg.begin += len;
        i++;
    }
    if(allfull){
        if(!valid && statusmap.empty()){
            deleteLater(PEER_LOST_ERR);
        }else{
            rwer->delEvents(RW_EVENT::READ);
        }
    }
}

bool File::finish(uint32_t flags, void* index){
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        statusmap.erase(id);
        return false;
    }
    return true;
}

void File::deleteLater(uint32_t errcode){
    evictMe();
    for(auto i:statusmap){
        assert(!i.second.req_ptr.expired());
        if(!i.second.responsed){
            HttpResHeader* res = new HttpResHeader(H503, sizeof(H503));
            res->index = i.second.req_index;
            i.second.req_ptr.lock()->response(res);
        }
        i.second.req_ptr.lock()->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}

void File::dump_stat(Dumper dp, void* param){
    dp(param, "File %p, %s, id=%d:\n", this, filename, req_id);
    for(const auto& i: statusmap){
        assert(!i.second.req_ptr.expired());
        dp(param, "0x%x: (%zd-%zd) %p, %p\n",
                i.first, i.second.rg.begin, i.second.rg.end,
                i.second.req_ptr.lock().get(), i.second.req_index);
    }
}


File::~File() {
    if(fd > 0){
        close(fd);
    }
}

std::weak_ptr<Responser> File::getfile(HttpReqHeader* req) {
    assert(!req->src.expired());
    auto req_ptr = req->src.lock();
    if(!req->getrange()){
        HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
        res->index = req->index;
        req_ptr->response(res);
        return std::weak_ptr<Responser>();
    }
    char filename[URLLIMIT];
    bool slash_end = req->filename.back() == '/';
    bool index_not_found = false;
    realpath(("./" + req->filename).c_str(), filename);
    HttpResHeader* res = nullptr;
    while(true){
        if(!startwith(filename, opt.rootdir)){
            LOGE("get file out of rootdir: %s\n", filename);
            res = new HttpResHeader(H403, sizeof(H403));
            goto ret;
        }
        if(filename == pathjoin(opt.rootdir, "status")){
            return std::dynamic_pointer_cast<Responser>((new Status())->shared_from_this());
        }
#ifdef ENABLE_GZIP_TEST
        if(filename == pathjoin(opt.rootdir, "test")){
            return std::dynamic_pointer_cast<Responser>((new GzipTest())->shared_from_this());
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
                    realpath(("./" + req->filename).c_str(), filename);
                    continue;
                }
                res = new HttpResHeader(H404, sizeof(H404));
            }else{
                res = new HttpResHeader(H500, sizeof(H500));
            }
            goto ret;
        }

        if(S_ISDIR(st.st_mode)){
            if(!slash_end){
                res = new HttpResHeader(H302, sizeof(H302));
                char location[FILENAME_MAX];
                snprintf(location, sizeof(location), "/%s/", req->filename.c_str());
                res->set("Location", location);
                goto ret;
            }
            if(!index_not_found && opt.index_file){
                realpath(("./" + req->filename + opt.index_file).c_str(), filename);
                continue;
            }
            if(!opt.autoindex){
                res = new HttpResHeader(H403, sizeof(H403));
                goto ret;
            }

            DIR* dir = opendir(filename);
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", filename, strerror(errno));
                res = new HttpResHeader(H500, sizeof(H500));
                goto ret;
            }
            res = new HttpResHeader(H200, sizeof(H200));
            res->set("Transfer-Encoding", "chunked");
            res->index = req->index;
            req_ptr->response(res);
            char buff[1024];
            req_ptr->Send((const void*)buff,
                           sprintf(buff, "<html>"
                           "<head><title>Index of %s</title></head>"
                           "<body><h1>Index of %s</h1><hr/><pre>",
                           req->filename.c_str(), req->filename.c_str()),
                           req->index);
            struct dirent *ptr;
            while((ptr = readdir(dir))){
                if(ptr->d_type == DT_DIR){
                    req_ptr->Send((const void*)buff,
                                   sprintf(buff, "<a href='%s/'>%s/</a><br/>", ptr->d_name, ptr->d_name),
                                   req->index);
                }else{
                    req_ptr->Send((const void*)buff,
                                   sprintf(buff, "<a href='%s'>%s</a><br/>", ptr->d_name, ptr->d_name),
                                   req->index);

                }
            }
            closedir(dir);
            req_ptr->Send((const void*)buff,
                           sprintf(buff, "</pre><hr></body></html>"),
                           req->index);
			req_ptr->Send((const void*)nullptr, 0, req->index);
            req_ptr->finish(NOERROR | DISCONNECT_FLAG, req->index);
            return std::weak_ptr<Responser>();
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", filename);
            res = new HttpResHeader(H403, sizeof(H403));
            goto ret;
        }
#ifdef ENABLE_CGI
#if __APPLE__
        if(suffix && strcmp(suffix, ".dylib") == 0){
#elif __linux__
        if(suffix && strcmp(suffix, ".so") == 0){
#else
        if(0){
#endif
            return getcgi(req, filename);
        }
#endif

        if(filemap.count(filename)){
            auto file = filemap[filename];
            if(!file.expired() && file.lock()->checkvalid()){
                return file;
            }
        }
        int fd = open(filename, O_RDONLY | O_CLOEXEC);
        if(fd < 0){
            LOGE("open file failed %s: %s\n", filename, strerror(errno));
            res = new HttpResHeader(H500, sizeof(H500));
            goto ret;
        }
        return std::dynamic_pointer_cast<Responser>((new File(filename, fd, &st))->shared_from_this());
    }
ret:
    assert(res);
    res->index = req->index;
    req_ptr->response(res);
    return std::weak_ptr<Responser>();
}
