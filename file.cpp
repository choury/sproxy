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




Range::Range(const char *range){
    if(range == nullptr) {
        return;
    }
    if(strncasecmp(range,"bytes=",6) != 0) {
        throw 0;
    }
    range += 6;
    enum{start,testtail,first,testsecond,second}status=start;
    ssize_t begin,end;
    while (1){
        switch (status){
        case start:
            begin = end = -1;
            if (*range == '-') {
                range ++;
                status = testtail;
            } else if (isdigit(*range)) {
                begin = 0;
                status = first;
            } else {
                throw 0;
            }
            break;
        case testtail:
            if (isdigit(*range)) {
                end = 0;
                status = second;
            } else {
                throw 0;
            }
            break;
        case first:
            if (*range == '-' ) {
                range ++;
                status = testsecond;
            } else if (isdigit(*range)) {
                begin *= 10;
                begin += *range - '0';
                range ++;
            } else {
                throw 0;
            }
            break;
        case testsecond:
            if (*range == 0) {
                add(begin,end);
                return;
            } else if (*range == ',') {
                add(begin,end);
                range ++;
                status = start;
            } else if(isdigit(*range)) {
                end = 0;
                status = second;
            }
            break;
        case second:
            if (*range == 0) {
                add(begin,end);
                return;
            } else if (*range == ',') {
                add(begin,end);
                range ++;
                status = start;
            } else if (isdigit(*range)){
                end *= 10 ;
                end += *range - '0';
                range ++;
            } else {
                throw 0;
            }
            break;
        }
    }
}

void Range::add(ssize_t begin, ssize_t end) {
    ranges.push_back(std::make_pair(begin,end));
}

size_t Range::size() {
    return ranges.size();
}


bool Range::calcu(size_t size) {
    for (size_t i=0;i < ranges.size();++i){
        if (ranges[i].first > (ssize_t)size-1) {
            return false;
        }
        if (ranges[i].first < 0) {
            if (ranges[i].second == 0) {
                return false;
            }
            ranges[i].first  = (int)size-ranges[i].second < 0 ? 0 : size-ranges[i].second;
            ranges[i].second = size-1;
        }
        if (ranges[i].second < 0) {
            ranges[i].second = size-1;
        }
        if (ranges[i].first > ranges[i].second) {
            ranges[i].first = 0;
            ranges[i].second = size-1;
        }
    }
    return true;
}


File::File(const char *fname) {
    //connect(guest, this);
    fd = eventfd(1, O_NONBLOCK);
    snprintf(filename, sizeof(filename), "%s", fname);

    handleEvent = (void (Con::*)(uint32_t))&File::openHE;
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

/*

File* File::getfile(HttpReqHeader &req, Guest* guest) {
    File* exist = dynamic_cast<File *>(guest);
    if (exist) {
        exist->clean(NOERROR, guest);
    }
    return new File(req, guest);
}

*/

int File::showerrinfo(int ret, const char* s) {
    if (ret < 0 && errno != EAGAIN) {
        LOGE("%s: %s\n", s, strerror(errno));
        return 1;
    }
    return 0;
}

Ptr File::request(HttpReqHeader& req) {
    guest_ptr = req.getsrc();
    return shared_from_this();
}


void File::openHE(uint32_t events) {
    Guest *guest = dynamic_cast<Guest *>(guest_ptr.get());
    if (guest == NULL) {
        goto err;
    }
    
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("file unkown error: %s\n", strerror(errno));
        goto err;
    }
    
    struct stat st;
    if (stat(filename, &st)) {
        LOGE("get file info failed: %s\n", strerror(errno));
        HttpResHeader res(H404, shared_from_this());
        guest->response(res);
        guest->Write((const void *)nullptr, 0, this);
        goto err;
    }
    if (S_ISREG(st.st_mode)) {
        int ffd = open(filename, O_RDONLY);
        if (ffd < 0) {
            LOGE("open file failed: %s\n", strerror(errno));
            HttpResHeader res(H500, shared_from_this());
            guest->response(res);
            goto err;
        }
        size = st.st_size;
        Range range(reqs.front().get("Range"));
        if (range.size() == 1 && range.calcu(st.st_size)){
            offset = range.ranges[0].first;
        } else if(range.size()){
            HttpResHeader res(H416, shared_from_this());
            char buff[100];
            snprintf(buff, sizeof(buff), "bytes */%lu", st.st_size);
            res.add("Content-Range", buff);
            guest->response(res);
            goto err;
        }
        mapptr = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, ffd, 0);
        if(mapptr == nullptr){
            LOGE("lseek file failed: %s\n", strerror(errno));
            HttpResHeader res(H500, shared_from_this());
            guest->response(res);
            goto err;
        }else if(range.size()){
            HttpResHeader res(H206, shared_from_this());
            char buff[100];
            snprintf(buff, sizeof(buff), "bytes %lu-%lu/%lu",
                     range.ranges[0].first, range.ranges[0].second, st.st_size);
            res.add("Content-Range", buff);
            size_t leftsize = range.ranges[0].second - range.ranges[0].first+1;
            snprintf(buff, sizeof(buff), "%lu", leftsize);
            res.add("Content-Length", buff);
            guest->response(res);
        }else{
            HttpResHeader res(H200, shared_from_this());
            char buff[100];
            snprintf(buff, sizeof(buff), "%lu", size);
            res.add("Content-Length", buff);
            guest->response(res);
        }
        close(ffd);
    } else if (S_ISDIR(st.st_mode)) {
        strcat(filename, "/index.html");
        openHE(events);
    }
    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    return;
err:
    clean(INTERNAL_ERR, this);
    return;
}


void File::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    Guest *guest = dynamic_cast<Guest *>(reqs.front().getsrc().get());
    if (guest == NULL) {
        reqs.pop();
        return;
    }
    
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("file unkown error: %s\n", strerror(errno));
        clean(INTERNAL_ERR, this);
        return;
    }
    
    if (events & EPOLLIN) {
        if (offset == size) {
            guest->Write((const void*)nullptr, 0, this);
            return;
        }
        int len = Min(guest->bufleft(this), size - offset);
        if (len <= 0) {
            LOGE("The guest's write buff is full\n");
            guest->wait(this);
            return;
        }
        len = guest->Write((const char *)mapptr+offset, len, this);
        offset += len;
    }
    if (events & EPOLLOUT) {
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    
}


File::~File() {
    if (mapptr) {
        munmap(mapptr, size);
    }
}

