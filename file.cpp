#include "file.h"
#include "net.h"
#include "requester.h"

#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/mman.h>


using std::vector;
using std::pair;


std::map<std::string, File *> filemap;

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
    return;
err:
    if(ffd > 0){
        close(ffd);
    }
    HttpResHeader res(errinfo);
    res.http_id = req.http_id;
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


uint32_t File::request(HttpReqHeader&& req) {
    FileStatus status;
    status.req_ptr = req.src;
    status.req_id = req.http_id;
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
    return req_id++;
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
                    res.http_id = i->second.req_id;
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
                    res.http_id = i->second.req_id;
                    requester->response(std::move(res));
                }else if(checkrange(rg, st.st_size)){
                    HttpResHeader res(H206);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes %zu-%zu/%zu",
                             rg.begin, rg.end, st.st_size);
                    res.add("Content-Range", buff);
                    size_t leftsize = rg.end - rg.begin+1;
                    res.add("Content-Length", leftsize);
                    res.http_id = i->second.req_id;
                    requester->response(std::move(res));
                }else{
                    HttpResHeader res(H416);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes */%zu", st.st_size);
                    res.add("Content-Range", buff);
                    res.http_id = i->second.req_id;
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
                requester->Write((const void*)nullptr, 0, i->second.req_id);
                i = statusmap.erase(i);
                continue;
            }
            int len = Min(requester->bufleft(i->second.req_id), rg.end - rg.begin + 1);
            if (len <= 0) {
                LOGE("The requester's write buff is full\n");
                requester->wait(i->second.req_id);
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
            len = requester->Write(buff, len, i->second.req_id);
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

void File::clean(uint32_t errcode, uint32_t id){
    if(id == 0){
        for(auto i:statusmap){
            if(!i.second.responsed){
                HttpResHeader res(H503);
                res.http_id = i.second.req_id;
                i.second.req_ptr->response(std::move(res));
            }
            i.second.req_ptr->clean(errcode, i.second.req_id);
        }
        statusmap.clear();
        return Peer::clean(errcode, id);
    }else{
        statusmap.erase(id);
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
        res.http_id = req.http_id;
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
