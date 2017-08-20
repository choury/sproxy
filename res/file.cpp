#include "file.h"
#include "cgi.h"
#include "misc/net.h"
#include "req/requester.h"

//#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
//#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/eventfd.h>
//#include <sys/stat.h>
//#include <sys/mman.h>


using std::vector;
using std::pair;


static std::map<std::string, File *> filemap;

//from https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Complete_list_of_MIME_types
const static std::map<std::string, const char*> mimetype={
    {".aac", "audio/aac"},
    {".abw", "application/x-abiword"},
    {".arc", "application/octet-stream"},
    {".avi", "video/x-msvideo"},
    {".azw", "application/vnd.amazon.ebook"},
    {".bin", "application/octet-stream"},
    {".bz", "application/x-bzip"},
    {".bz2", "application/x-bzip2"},
    {".csh", "application/x-csh"},
    {".css", "text/css"},
    {".csv", "text/csv"},
    {".doc", "application/msword"},
    {".epub", "application/epub+zip"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".ico", "image/x-icon"},
    {".ics", "text/calendar"},
    {".jar", "application/java-archive"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".js", "application/javascript"},
    {".json", "application/json"},
    {".mid", "audio/midi"},
    {".midi", "audio/midi"},
    {".mpeg", "video/mpeg"},
    {".mpkg", "application/vnd.apple.installer+xml"},
    {".odp", "application/vnd.oasis.opendocument.presentation"},
    {".ods", "application/vnd.oasis.opendocument.spreadsheet"},
    {".odt", "application/vnd.oasis.opendocument.text"},
    {".oga", "audio/ogg"},
    {".ogv", "video/ogg"},
    {".ogx", "application/ogg"},
    {".pdf", "application/pdf"},
    {".ppt", "application/vnd.ms-powerpoint"},
    {".rar", "application/x-rar-compressed"},
    {".rtf", "application/rtf"},
    {".sh", "application/x-sh"},
    {".svg", "image/svg+xml"},
    {".swf", "application/x-shockwave-flash"},
    {".tar", "application/x-tar"},
    {".tif", "image/tiff"},
    {".tiff", "image/tiff"},
    {".ttf", "application/x-font-ttf"},
    {".vsd", "application/vnd.visio"},
    {".wav", "audio/x-wav"},
    {".weba", "audio/webm"},
    {".webm", "video/webm"},
    {".webp", "image/webp"},
    {".woff", "application/x-font-woff"},
    {".xhtml", "application/xhtml+xml"},
    {".xls", "application/vnd.ms-excel"},
    {".xml", "application/xml"},
    {".xul", "application/vnd.mozilla.xul+xml"},
    {".zip", "application/zip"},
    {".3gp", "video/3gpp"},
    {".3g2", "video/3gpp2"},
    {".7z", "application/x-7z-compressed"},
};

bool checkrange(Range& rg, size_t size) {
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


#if 0
File::File(HttpReqHeader* req) {


    fd = eventfd(1, O_NONBLOCK);
    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    filemap[filename] = this;
    suffix = strrchr(filename, '.');
    return;
err:
    if(ffd > 0){
        close(ffd);
    }
    res->index = req->index;
    req->src->response(res);
    throw 0;
}
#endif

File::File(const char* fname, int ffd, const struct stat* st):ffd(ffd), st(*st){
    snprintf(filename, sizeof(filename), "./%s", fname);
    strcpy(filename, fname);
    fd = eventfd(1, O_NONBLOCK);
    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    filemap[filename] = this;
    suffix = strrchr(filename, '.');
}


bool File::checkvalid() {
    struct stat nt;
    if(stat(filename, &nt)){
        valid = false;
    }else{
        valid = nt.st_mtime == st.st_mtime && nt.st_ino == st.st_ino;
    }
    if(!valid){
        updateEpoll(EPOLLIN);
    }
    return valid;
}

int32_t File::bufleft(void*){
    return 0;
}

//discard everything!
ssize_t File::Send(void* buff, size_t size, void*) {
    p_free(buff);
    return size;
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
    updateEpoll(EPOLLIN);
    statusmap[req_id] = status;
    delete req;
    return reinterpret_cast<void*>(req_id++);
}


void File::defaultHE(uint32_t events) {
    if(statusmap.empty()){
        if(!valid){
            deleteLater(PEER_LOST_ERR);
        }else{
            updateEpoll(0);
        }
        return;
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("file unkown error: %s\n", strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLOUT) {
        updateEpoll(EPOLLIN);
    }

    if (events & EPOLLIN) {
        bool allfull = true;
        for(auto i = statusmap.begin();i!=statusmap.end();){
            Range& rg = i->second.rg;
            Requester *requester = i->second.req_ptr;
            assert(requester);
            if (!i->second.responsed){
                if(i->second.modified_since >= st.st_mtime){
                    HttpResHeader* res = new HttpResHeader(H304);
                    char buff[100];
                    strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
                    res->add("Last-Modified", buff);
                    res->index = i->second.req_index;
                    requester->response(res);
                    requester->finish(NOERROR | DISCONNECT_FLAG, i->second.req_index);
                    i = statusmap.erase(i);
                    continue;
                }
                if(rg.begin == -1 && rg.end == -1){
                    rg.begin = 0;
                    rg.end = st.st_size - 1;
                    HttpResHeader* res = new HttpResHeader(H200);
                    res->add("Content-Length", st.st_size);
                    char buff[100];
                    strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime((const time_t *)&st.st_mtime));
                    res->add("Last-Modified", buff);
                    if(suffix && mimetype.count(suffix)){
                        res->add("Content-Type", mimetype.at(suffix));
                    }
                    res->index = i->second.req_index;
                    requester->response(res);
                }else if(checkrange(rg, st.st_size)){
                    HttpResHeader* res = new HttpResHeader(H206);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes %zd-%zd/%jd",
                             rg.begin, rg.end, (intmax_t)st.st_size);
                    res->add("Content-Range", buff);
                    size_t leftsize = rg.end - rg.begin+1;
                    res->add("Content-Length", leftsize);
                    if(suffix && mimetype.count(suffix)){
                        res->add("Content-Type", mimetype.at(suffix));
                    }
                    res->index = i->second.req_index;
                    requester->response(res);
                }else{
                    HttpResHeader* res = new HttpResHeader(H416);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
                    res->add("Content-Range", buff);
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
                LOGE("The requester's write buff is full\n");
                i++;
                continue;
            }
            allfull = false;
            char *buff = (char *)p_malloc(len);
            len = pread(ffd, buff, len, rg.begin);
            if(len <= 0){
                LOGE("file pread error: %s\n", strerror(errno));
                deleteLater(READ_ERR);
                return;
            }
            len = requester->Send(buff, len, i->second.req_index);
            rg.begin += len;
            i++;
        }
        if(allfull){
            updateEpoll(0);
        }
    }
}

bool File::finish(uint32_t flags, void* index){
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode){
        statusmap.erase(id);
        return false;
    }
    return true;
}

void File::deleteLater(uint32_t errcode){
   for(auto i:statusmap){
        if(!i.second.responsed){
            HttpResHeader* res = new HttpResHeader(H503);
            res->index = i.second.req_index;
            i.second.req_ptr->response(res);
        }
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}

void File::dump_stat(){
    LOG("File %p, %s, id=%d:\n", this, filename, req_id);
    for(auto i: statusmap){
        LOG("0x%x: (%zd-%zd) %p, %p\n",
            i.first, i.second.rg.begin, i.second.rg.end,
            i.second.req_ptr, i.second.req_index);
    }
}


File::~File() {
    if(ffd > 0){
        close(ffd);
    }
    filemap.erase(filename);
}

Responser* File::getfile(HttpReqHeader* req) {
    if(!req->getrange()){
        HttpResHeader* res = new HttpResHeader(H400);
        res->index = req->index;
        req->src->response(res);
        return nullptr;
    }
    char filename[URLLIMIT];
    bool slash_end = endwith(req->filename.c_str(), "/"), index_not_found = false;
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
                res = new HttpResHeader(H404);
            }else{
                res = new HttpResHeader(H500);
            }
            break;
        }

        if(S_ISDIR(st.st_mode)){
            if(!slash_end){
                res = new HttpResHeader(H301);
                char location[FILENAME_MAX];
                snprintf(location, sizeof(location), "/%s/", req->filename.c_str());
                res->add("Location", location);
                break;
            }
            if(slash_end && !index_not_found && index_file){
                snprintf(filename, sizeof(filename), "./%s%s", req->filename.c_str(), index_file);
                continue;
            }
            if(slash_end && !autoindex){
                res = new HttpResHeader(H403);
                break;
            }

            DIR* dir = opendir(filename);
            if(dir == nullptr){
                LOGE("open %s dir failed: %s\n", filename, strerror(errno));
                res = new HttpResHeader(H500);
                break;
            }
            res = new HttpResHeader(H200);
            res->add("Transfer-Encoding", "chunked");
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
            req->src->Send((const void*)nullptr, 0, req->index);
            return nullptr;
        }

        if(!S_ISREG(st.st_mode)){
            LOGE("access to no regular file %s\n", filename);
            res = new HttpResHeader(H403);
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
            res = new HttpResHeader(H500);
            break;
        }
        return new File(filename, fd, &st);
    }
    assert(res);
    res->index = req->index;
    req->src->response(res);
    return nullptr;
}
