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


Ranges::Ranges(const char *range_str){
    if(range_str == nullptr) {
        return;
    }
    if(strncasecmp(range_str,"bytes=",6) != 0) {
        throw 0;
    }
    range_str += 6;
    enum class Status{
        start,testtail,first,testsecond,second
    }status= Status::start;
    ssize_t begin = -1,end = -1;
    while (1){
        switch (status){
        case Status::start:
            begin = end = -1;
            if (*range_str == '-') {
                range_str ++;
                status = Status::testtail;
            } else if (isdigit(*range_str)) {
                begin = 0;
                status = Status::first;
            } else {
                throw 0;
            }
            break;
        case Status::testtail:
            if (isdigit(*range_str)) {
                end = 0;
                status = Status::second;
            } else {
                throw 0;
            }
            break;
        case Status::first:
            if (*range_str == '-' ) {
                range_str ++;
                status = Status::testsecond;
            } else if (isdigit(*range_str)) {
                begin *= 10;
                begin += *range_str - '0';
                range_str ++;
            } else {
                throw 0;
            }
            break;
        case Status::testsecond:
            if (*range_str == 0) {
                add(begin,end);
                return;
            } else if (*range_str == ',') {
                add(begin,end);
                range_str ++;
                status = Status::start;
            } else if(isdigit(*range_str)) {
                end = 0;
                status = Status::second;
            }
            break;
        case Status::second:
            if (*range_str == 0) {
                add(begin,end);
                return;
            } else if (*range_str == ',') {
                add(begin,end);
                range_str ++;
                status = Status::start;
            } else if (isdigit(*range_str)){
                end *= 10 ;
                end += *range_str - '0';
                range_str ++;
            } else {
                throw 0;
            }
            break;
        }
    }
}

void Ranges::add(ssize_t begin, ssize_t end) {
    rgs.push_back(range{begin,end});
}

size_t Ranges::size() {
    return rgs.size();
}


bool Ranges::calcu(size_t size) {
    for (size_t i=0;i < rgs.size();++i){
        if (rgs[i].begin > (ssize_t)size-1) {
            return false;
        }
        if (rgs[i].begin < 0) {
            if (rgs[i].end == 0) {
                return false;
            }
            rgs[i].begin  = (int)size-rgs[i].end < 0 ? 0 : size-rgs[i].end;
            rgs[i].end = size-1;
        }
        if (rgs[i].end < 0) {
            rgs[i].end = size-1;
        }
        if (rgs[i].begin > rgs[i].end) {
            rgs[i].begin = 0;
            rgs[i].end = size-1;
        }
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
    try{
        Ranges ranges(req.get("Range"));
        FileStatus status;
        status.req = req;
        if (ranges.size() == 1 && ranges.calcu(size)){
            status.rg = ranges.rgs[0];
        } else if(ranges.size()){
            HttpResHeader res(H416, this);
            char buff[100];
            snprintf(buff, sizeof(buff), "bytes */%zu", size);
            res.add("Content-Range", buff);
            res.http_id = req.http_id;
            requester->response(std::move(res));
            return 0;
        }
        if(ranges.size()){
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
        updateEpoll(EPOLLIN);
        statusmap[req_id] = status;
    }catch(...){
        HttpResHeader res(H400, this);
        res.http_id = req.http_id;
        requester->response(std::move(res));
        return 0;
    }
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
            HttpReqHeader &req = i->second.req;
            range& rg = i->second.rg;
            Requester *requester = dynamic_cast<Requester *>(req.src);
            if (requester == NULL) {
                i = statusmap.erase(i);
                continue;
            }
            if (rg.begin > rg.end) {
                requester->Write((const void*)nullptr, 0, req.http_id);
                i = statusmap.erase(i);
                continue;
            }
            int len = Min(requester->bufleft(req.http_id), rg.end - rg.begin + 1);
            if (len <= 0) {
                LOGE("The requester's write buff is full\n");
                requester->wait(req.http_id);
                i++;
                continue;
            }
            allfull = false;
            len = requester->Write((const char *)mapptr+rg.begin, len, req.http_id);
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

