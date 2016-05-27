#include "file.h"
#include "net.h"
#include "guest.h"

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
    enum{start,testtail,first,testsecond,second}status=start;
    ssize_t begin,end;
    while (1){
        switch (status){
        case start:
            begin = end = -1;
            if (*range_str == '-') {
                range_str ++;
                status = testtail;
            } else if (isdigit(*range_str)) {
                begin = 0;
                status = first;
            } else {
                throw 0;
            }
            break;
        case testtail:
            if (isdigit(*range_str)) {
                end = 0;
                status = second;
            } else {
                throw 0;
            }
            break;
        case first:
            if (*range_str == '-' ) {
                range_str ++;
                status = testsecond;
            } else if (isdigit(*range_str)) {
                begin *= 10;
                begin += *range_str - '0';
                range_str ++;
            } else {
                throw 0;
            }
            break;
        case testsecond:
            if (*range_str == 0) {
                add(begin,end);
                return;
            } else if (*range_str == ',') {
                add(begin,end);
                range_str ++;
                status = start;
            } else if(isdigit(*range_str)) {
                end = 0;
                status = second;
            }
            break;
        case second:
            if (*range_str == 0) {
                add(begin,end);
                return;
            } else if (*range_str == ',') {
                add(begin,end);
                range_str ++;
                status = start;
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
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    if (stat(req.filename, &st)) {
        LOGE("get file info failed: %s\n", strerror(errno));
        errinfo = H404;
        goto err;
    }
    if (S_ISREG(st.st_mode)) {
        int ffd = open(req.filename, O_RDONLY);
        if (ffd < 0) {
            LOGE("open file failed: %s\n", strerror(errno));
            errinfo = H500;
            goto err;
        }
        size = st.st_size;
        mapptr = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, ffd, 0);
        if(mapptr == nullptr){
            LOGE("mapptr file failed: %s\n", strerror(errno));
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
    guest->response(res);
    throw 0;
}


File* File::getfile(HttpReqHeader &req) {
    if(filemap.count(req.filename)){
        return filemap[req.filename];
    }else{
        return new File(req);
    }
}


int File::showerrinfo(int ret, const char* s) {
    if (ret < 0 && errno != EAGAIN) {
        LOGE("%s: %s\n", s, strerror(errno));
        return 1;
    }
    return 0;
}

Ptr File::request(HttpReqHeader& req) {
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    Ranges ranges(req.get("Range"));
    range rg;
    if (ranges.size() == 1 && ranges.calcu(size)){
        rg = ranges.rgs[0];
    } else if(ranges.size()){
        HttpResHeader res(H416, shared_from_this());
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes */%lu", size);
        res.add("Content-Range", buff);
        res.http_id = req.http_id;
        guest->response(res);
        return shared_from_this();
    }
    if(ranges.size()){
        HttpResHeader res(H206, shared_from_this());
        char buff[100];
        snprintf(buff, sizeof(buff), "bytes %lu-%lu/%lu",
                 rg.begin, rg.end, size);
        res.add("Content-Range", buff);
        size_t leftsize = rg.end - rg.begin+1;
        res.add("Content-Length", leftsize);
        res.http_id = req.http_id;
        guest->response(res);
    }else{
        rg.begin = 0;
        rg.end = size - 1;
        HttpResHeader res(H200, shared_from_this());
        res.add("Content-Length", size);
        res.http_id = req.http_id;
        guest->response(res);
    }
    updateEpoll(EPOLLIN);
    reqs.push_back(std::make_pair(req, rg));
    return shared_from_this();
}


void File::defaultHE(uint32_t events) {
    if(reqs.empty()){
        updateEpoll(0);
        return;
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("file unkown error: %s\n", strerror(errno));
        clean(INTERNAL_ERR, this);
        return;
    }
    
    if (events & EPOLLIN) {
        bool allfull = true;
        for(auto i = reqs.begin();i!=reqs.end();){
            HttpReqHeader &req = i->first;
            range& rg = i->second;
            Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
            if (guest == NULL) {
                i = reqs.erase(i);
                continue;
            }
            if (rg.begin > rg.end) {
                guest->Write((const void*)nullptr, 0, this, req.http_id);
                i = reqs.erase(i);
                continue;
            }
            int len = Min(guest->bufleft(this), rg.end - rg.begin + 1);
            if (len <= 0) {
                LOGE("The guest's write buff is full\n");
                guest->wait(this);
                i++;
                continue;
            }
            allfull = false;
            len = guest->Write((const char *)mapptr+rg.begin, len, this, req.http_id);
            rg.begin += len;
            i++;
        }
        if(!allfull){
            updateEpoll(EPOLLIN);
        }
    }
    if (events & EPOLLOUT) {
        updateEpoll(EPOLLIN);
    }
}

void File::clean(uint32_t errcode, Peer* who, uint32_t id){
    if(who == this)
        return Peer::clean(errcode, who, id);
}

File::~File() {
    if (mapptr) {
        munmap(mapptr, size);
    }
    filemap.erase(filename);
}

