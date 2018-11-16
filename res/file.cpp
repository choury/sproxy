#include "file.h"
#include "cgi.h"
#include "status.h"
#include "req/requester.h"
#include "misc/simpleio.h"
#include "misc/net.h"
#include "misc/util.h"

#ifdef ENABLE_GZIP_TEST
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
#include <sys/eventfd.h>


using std::vector;
using std::pair;


static std::map<std::string, File *> filemap;
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
    if (rg.begin > rg.end) {
        return false;
    }
    return true;
}

static void loadmine(){
    std::ifstream mimefile("/etc/mime.types");
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
        if(type == "" || type[0] == '#'){
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
    int evfd = eventfd(1, O_NONBLOCK);
    if(evfd < 0){
        LOGE("create evventfd failed: %s\n", strerror(errno));
        throw 0;
    }
    rwer = new PacketRWer(evfd, [this](int ret, int code){
        LOGE("file error: %d/%d\n", ret, code);
        deleteLater(ret);
    });
    if(filemap.empty()){
        loadmine();
    }
    strcpy(filename, fname);
    filemap[filename] = this;
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
        rwer->addEpoll(EPOLLIN);
    }
    return valid;
}

void File::evictMe(){
    if(filemap.count(filename) == 0){
        return;
    }
    if(filemap[filename] != this){
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
    if (req->ranges.size()){
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
    rwer->addEpoll(EPOLLIN);
    return reinterpret_cast<void*>(req_id++);
}


void File::readHE(size_t len) {
    rwer->consume(nullptr, len);
    rwer->buffer_insert(rwer->buffer_end(), "FILEFILE", 8);

    bool allfull = true;
    for(auto i = statusmap.begin();i!=statusmap.end();){
        Range& rg = i->second.rg;
        Requester *requester = i->second.req_ptr;
        assert(requester);
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
        char *buff = (char *)p_malloc(len);
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
            rwer->delEpoll(EPOLLIN);
        }
    }
}

void File::finish(uint32_t flags, void* index){
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        statusmap.erase(id);
    }
}

void File::deleteLater(uint32_t errcode){
    evictMe();
    for(auto i:statusmap){
        if(!i.second.responsed){
            HttpResHeader* res = new HttpResHeader(H503, sizeof(H503));
            res->index = i.second.req_index;
            i.second.req_ptr->response(res);
        }
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}

void File::dump_stat(Dumper dp, void* param){
    dp(param, "File %p, %s, id=%d:\n", this, filename, req_id);
    for(auto i: statusmap){
        dp(param, "0x%x: (%zd-%zd) %p, %p\n",
                i.first, i.second.rg.begin, i.second.rg.end,
                i.second.req_ptr, i.second.req_index);
    }
}


File::~File() {
    if(fd > 0){
        close(fd);
    }
}

Responser* File::getfile(HttpReqHeader* req) {
    if(!req->getrange()){
        HttpResHeader* res = new HttpResHeader(H400, sizeof(H400));
        res->index = req->index;
        req->src->response(res);
        return nullptr;
    }
    if(req->filename == "status"){
        return new Status();
    }

#ifdef ENABLE_GZIP_TEST
    if(req->filename == "test"){
        return new GzipTest();
    }
#endif

    char filename[URLLIMIT];
    bool slash_end = req->filename.back() == '/';
    bool index_not_found = false;
    snprintf(filename, sizeof(filename), "./%s", req->filename.c_str());
    HttpResHeader* res = nullptr;
    while(true){
        struct stat st;
        if(stat(filename, &st) < 0){
            LOGE("get file stat failed %s: %s\n", filename, strerror(errno));
            if(errno == ENOENT){
                if(slash_end && !endwith(filename, "/") && autoindex){
                    index_not_found = true;
                    snprintf(filename, sizeof(filename), "./%s", req->filename.c_str());
                    continue;
                }
                res = new HttpResHeader(H404, sizeof(H404));
            }else{
                res = new HttpResHeader(H500, sizeof(H500));
            }
            break;
        }

        if(S_ISDIR(st.st_mode)){
            if(!slash_end){
                res = new HttpResHeader(H301, sizeof(H301));
                char location[FILENAME_MAX];
                snprintf(location, sizeof(location), "/%s/", req->filename.c_str());
                res->set("Location", location);
                break;
            }
            if(!index_not_found && index_file){
                snprintf(filename, sizeof(filename), "./%s%s", req->filename.c_str(), index_file);
                continue;
            }
            if(!autoindex){
                res = new HttpResHeader(H403, sizeof(H403));
                break;
            }

            DIR* dir = opendir(filename);
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", filename, strerror(errno));
                res = new HttpResHeader(H500, sizeof(H500));
                break;
            }
            res = new HttpResHeader(H200, sizeof(H200));
            res->set("Transfer-Encoding", "chunked");
            res->index = req->index;
            req->src->response(res);
            char buff[1024];
            req->src->Send((const void*)buff,
                           sprintf(buff, "<html>"
                           "<head><title>Index of %s</title></head>"
                           "<body><h1>Index of %s</h1><hr/><pre>",
                           req->filename.c_str(), req->filename.c_str()),
                           req->index);
            struct dirent *ptr;
            while((ptr = readdir(dir))){
                if(ptr->d_type == DT_DIR){
                    req->src->Send((const void*)buff,
                                   sprintf(buff, "<a href='%s/'>%s/</a><br/>", ptr->d_name, ptr->d_name),
                                   req->index);
                }else{
                    req->src->Send((const void*)buff,
                                   sprintf(buff, "<a href='%s'>%s</a><br/>", ptr->d_name, ptr->d_name),
                                   req->index);

                }
            }
            closedir(dir);
            req->src->Send((const void*)buff,
                           sprintf(buff, "</pre><hr></body></html>"),
                           req->index);
            req->src->finish(NOERROR | DISCONNECT_FLAG, req->index);
            return nullptr;
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", filename);
            res = new HttpResHeader(H403, sizeof(H403));
            break;
        }
        if(endwith(filename, ".so")){
            return getcgi(req, filename);
        }

        if(filemap.count(filename)){
            File *file = filemap[filename];
            if(file->checkvalid()){
                return file;
            }
        }
        int fd = open(filename, O_RDONLY);
        if(fd < 0){
            LOGE("open file failed %s: %s\n", filename, strerror(errno));
            res = new HttpResHeader(H500, sizeof(H500));
            break;
        }
        return new File(filename, fd, &st);
    }
    assert(res);
    res->index = req->index;
    req->src->response(res);
    return nullptr;
}
