#include "file.h"
#include "misc/net.h"
#include "req/requester.h"

#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/mman.h>


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


File::File(HttpReqHeader& req) {
    const char *errinfo = nullptr;
    ffd = open(req.filename, O_RDONLY);
    if (ffd < 0) {
        LOGE("open file failed %s: %m\n", req.filename);
        if(errno == ENOENT){
            errinfo = H404;
        }else{
            errinfo = H500;
        }
        goto err;
    }
    if (fstat(ffd, &st)) {
        LOGE("get file info failed %s: %m\n", req.filename);
        errinfo = H500;
        goto err;
    }

    if(!S_ISREG(st.st_mode)){
        LOGE("access to no regular file %s\n", req.filename);
        errinfo = H500;
        goto err;
    }

    fd = eventfd(1, O_NONBLOCK);
    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    snprintf(filename, sizeof(filename), "%s", req.filename);
    filemap[filename] = this;
    suffix = strrchr(filename, '.');
    return;
err:
    if(ffd > 0){
        close(ffd);
    }
    HttpResHeader res(errinfo);
    res.index = req.index;
    req.src->response(std::move(res));
    throw 0;
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


void* File::request(HttpReqHeader&& req) {
    FileStatus status;
    status.req_ptr = req.src;
    status.req_index = req.index;
    status.head_only = req.ismethod("HEAD");
    status.responsed = false;
    if (req.ranges.size()){
        status.rg = req.ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
    if(req.get("If-Modified-Since")){
        struct tm tp;
        strptime(req.get("If-Modified-Since"), "%a, %d %b %Y %H:%M:%S GMT", &tp);
        status.modified_since = timegm(&tp);
    }else{
        status.modified_since = 0;
    }
    updateEpoll(EPOLLIN);
    statusmap[req_id] = status;
    return reinterpret_cast<void*>(req_id++);
}


void File::defaultHE(uint32_t events) {
    if(statusmap.empty()){
        if(!valid){
            clean(NOERROR, 0);
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
        clean(INTERNAL_ERR, 0);
        return;
    }

    if (events & EPOLLIN) {
        bool allfull = true;
        for(auto i = statusmap.begin();i!=statusmap.end();){
            Range& rg = i->second.rg;
            Requester *requester = i->second.req_ptr;
            assert(requester);
            if (!i->second.responsed){
                if(i->second.modified_since >= st.st_mtime){
                    HttpResHeader res(H304);
                    char buff[100];
                    strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&st.st_mtime));
                    res.add("Last-Modified", buff);
                    res.index = i->second.req_index;
                    requester->response(std::move(res));
                    i = statusmap.erase(i);
                    continue;
                }
                if(rg.begin == -1 && rg.end == -1){
                    rg.begin = 0;
                    rg.end = st.st_size - 1;
                    HttpResHeader res(H200);
                    res.add("Content-Length", st.st_size);
                    char buff[100];
                    strftime(buff, sizeof(buff), "%a, %d %b %Y %H:%M:%S GMT", gmtime(&st.st_mtime));
                    res.add("Last-Modified", buff);
                    if(suffix && mimetype.count(suffix)){
                        res.add("Content-Type", mimetype.at(suffix));
                    }
                    res.index = i->second.req_index;
                    requester->response(std::move(res));
                }else if(checkrange(rg, st.st_size)){
                    HttpResHeader res(H206);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes %zu-%zu/%jd",
                             rg.begin, rg.end, (intmax_t)st.st_size);
                    res.add("Content-Range", buff);
                    size_t leftsize = rg.end - rg.begin+1;
                    res.add("Content-Length", leftsize);
                    if(suffix && mimetype.count(suffix)){
                        res.add("Content-Type", mimetype.at(suffix));
                    }
                    res.index = i->second.req_index;
                    requester->response(std::move(res));
                }else{
                    HttpResHeader res(H416);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes */%jd", (intmax_t)st.st_size);
                    res.add("Content-Range", buff);
                    res.index = i->second.req_index;
                    requester->response(std::move(res));
                    i = statusmap.erase(i);
                    continue;
                }
                if(i->second.head_only){
                    i = statusmap.erase(i);
                    continue;
                }else{
                    i->second.responsed = true;
                }
            }
            if (rg.begin > rg.end) {
                requester->Write((const void*)nullptr, 0, i->second.req_index);
                i = statusmap.erase(i);
                continue;
            }
            int len = Min(requester->bufleft(i->second.req_index), rg.end - rg.begin + 1);
            if (len <= 0) {
                LOGE("The requester's write buff is full\n");
                requester->wait(i->second.req_index);
                i++;
                continue;
            }
            allfull = false;
            char *buff = (char *)p_malloc(len);
            len = pread(ffd, buff, len, rg.begin);
            if(len <= 0){
                clean(INTERNAL_ERR, 0);
                return;
            }
            len = requester->Write(buff, len, i->second.req_index);
            rg.begin += len;
            i++;
        }
        if(allfull){
            updateEpoll(0);
        }
    }
    if (events & EPOLLOUT) {
        updateEpoll(EPOLLIN);
    }
}

void File::clean(uint32_t errcode, void* index){
    if(index == nullptr){
        for(auto i:statusmap){
            if(!i.second.responsed){
                HttpResHeader res(H503);
                res.index = i.second.req_index;
                i.second.req_ptr->response(std::move(res));
            }
            i.second.req_ptr->clean(errcode, i.second.req_index);
        }
        statusmap.clear();
        return Peer::clean(errcode, index);
    }else{
        statusmap.erase((uint32_t)(long)index);
    }
}

File::~File() {
    if(ffd > 0){
        close(ffd);
    }
    filemap.erase(filename);
}

File* File::getfile(HttpReqHeader& req) {
    if(!req.getrange()){
        HttpResHeader res(H400);
        res.index = req.index;
        req.src->response(std::move(res));
        return nullptr;
    }
    if(filemap.count(req.filename)){
        File *file = filemap[req.filename];
        if(file->checkvalid()){
            return file;
        }
    }
    try{
        return new File(req);
    }catch(...){
        return nullptr;
    }
}
