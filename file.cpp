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
        rg.begin = 0;
        rg.end = size-1;
    }
    return true;
}




File::File(HttpReqHeader& req) {
    struct stat st;
    const char *errinfo = nullptr;
    Requester *requester = dynamic_cast<Requester *>(req.src);
    if (stat(req.filename, &st)) {
        LOGE("get file info failed %s: %m\n", req.filename);
        errinfo = H404;
        goto err;
    }
    if (S_ISREG(st.st_mode)) {
        int ffd = open(req.filename, O_RDONLY);
        if (ffd < 0) {
            LOGE("open file failed %s: %m\n", req.filename);
            errinfo = H500;
            goto err;
        }
        size = st.st_size;
        mapptr = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, ffd, 0);
        if(mapptr == nullptr){
            LOGE("mapptr file failed %s: %m\n", req.filename);
            errinfo = H500;
            close(ffd);
            goto err;
        }
        close(ffd);
    }else{
        errinfo = H404;
        goto err;
    }

    fd = eventfd(1, O_NONBLOCK);

    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    snprintf(filename, sizeof(filename), "%s", req.filename);
    filemap[filename] = this;
    return;
err:
    HttpResHeader res(errinfo);
    res.http_id = req.http_id;
    requester->response(std::move(res));
    throw 0;
}


File* File::getfile(HttpReqHeader& req) {
    Requester* requester = dynamic_cast<Requester *>(req.src);
    assert(requester);
    if(!req.getrange()){
        HttpResHeader res(H400);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return nullptr;
    }
    if(filemap.count(req.filename)){
        return filemap[req.filename];
    }else{
        try{
            return new File(req);
        }catch(...){
            return nullptr;
        }
    }
}


uint32_t File::request(HttpReqHeader&& req) {
    Requester *requester = dynamic_cast<Requester *>(req.src);
    assert(requester);
    FileStatus status;
    status.req_ptr = requester;
    status.req_id = req.http_id;
    status.responsed = false;
    if (req.ranges.size()){
        status.rg = req.ranges[0];
    }else{
        status.rg.begin = -1;
        status.rg.end = - 1;
    }
#if 0
    if (req.ranges.size() == 1 && checkrange(req.ranges[0], size)){
        status.rg = req.ranges[0];
    } else if(req.ranges.size()){
        HttpResHeader res(H416, this);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes */%zu", size);
        res.add("Content-Range", buff);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return 0;
    }
    if(req.ranges.size()){
        HttpResHeader res(H206, this);
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes %zu-%zu/%zu",
                 status.rg.begin, status.rg.end, size);
        res.add("Content-Range", buff);
        size_t leftsize = status.rg.end - status.rg.begin+1;
        res.add("Content-Length", leftsize);
        res.http_id = req.http_id;
        requester->response(std::move(res));
    }else{
        status.rg.begin = 0;
        status.rg.end = size - 1;
        HttpResHeader res(H200, this);
        res.add("Content-Length", size);
        res.http_id = req.http_id;
        requester->response(std::move(res));
    }
#endif
    updateEpoll(EPOLLIN);
    statusmap[req_id] = status;
    return req_id++;
}


void File::defaultHE(uint32_t events) {
    if(statusmap.empty()){
        updateEpoll(0);
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
                if(checkrange(rg, size)){
                    if(rg.begin == -1 && rg.end == -1){
                        rg.begin = 0;
                        rg.end = size - 1;
                        HttpResHeader res(H200, this);
                        res.add("Content-Length", size);
                        res.http_id = i->second.req_id;
                        requester->response(std::move(res));
                    }else{
                        HttpResHeader res(H206, this);
                        char buff[100];
                        snprintf(buff, sizeof(buff), "bytes %zu-%zu/%zu",
                                 rg.begin, rg.end, size);
                        res.add("Content-Range", buff);
                        size_t leftsize = rg.end - rg.begin+1;
                        res.add("Content-Length", leftsize);
                        res.http_id = i->second.req_id;
                        requester->response(std::move(res));
                    }
                }else{
                    HttpResHeader res(H416, this);
                    char buff[100];
                    snprintf(buff, sizeof(buff), "bytes */%zu", size);
                    res.add("Content-Range", buff);
                    res.http_id = i->second.req_id;
                    requester->response(std::move(res));
                    i = statusmap.erase(i);
                    continue;
                }
                i->second.responsed = true;
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
            len = requester->Write((const char *)mapptr+rg.begin, len, i->second.req_id);
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
        return Peer::clean(errcode, id);
    }else{
        statusmap.erase(id);
    }
}

File::~File() {
    if (mapptr) {
        munmap(mapptr, size);
    }
    filemap.erase(filename);
}

