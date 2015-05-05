#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include "common.h"
#include "file.h"
#include "cgi.h"

using std::vector;
using std::pair;


class Range{
    void add(ssize_t begin,ssize_t end);
public:
    vector<pair<ssize_t,ssize_t>> ranges;
    Range(const char *range);
    size_t size();
    bool calcu(size_t size);
};

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
            ranges[i].first  = size-ranges[i].second < 0 ? 0 : size-ranges[i].second;
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


File::File(HttpReqHeader &req, Guest* guest):req(req) {
    fd = eventfd(1, O_NONBLOCK);
    char filename[URLLIMIT];
    snprintf(filename, sizeof(filename), "%s", req.filename);
    struct stat st;
repeat:
    if (stat(filename, &st)) {
        LOGE("get file info failed: %s\n", strerror(errno));
        guest->Write(this, H404, strlen(H404));
        throw 0;
    }
    if (S_ISREG(st.st_mode)) {
        ffd = open(filename, O_RDONLY);
        if (ffd < 0) {
            LOGE("open file failed: %s\n", strerror(errno));
            guest->Write(this, MISCERRTIP, strlen(MISCERRTIP));
            throw 0;
        }
        Range range(req.get("Range"));
        if(range.size() == 0){
            HttpResHeader res(H200);
            leftsize = st.st_size;
            snprintf((char *)wbuff, sizeof(wbuff), "%lu", leftsize);
            res.add("Content-Length", (char *)wbuff);
            guest->Write(this, wbuff, res.getstring(wbuff));
        } else if (range.size() == 1 && range.calcu(st.st_size)){
            if(lseek(ffd,range.ranges[0].first,SEEK_SET)<0){
                LOGE("lseek file failed: %s\n", strerror(errno));
                guest->Write(this, MISCERRTIP, strlen(MISCERRTIP));
                throw 0;
            }
            HttpResHeader res(H206);
            leftsize = range.ranges[0].second - range.ranges[0].first+1;
            snprintf((char *)wbuff, sizeof(wbuff), "bytes %lu-%lu/%lu", 
                     range.ranges[0].first, range.ranges[0].second, st.st_size);
            res.add("Content-Range",(char *)wbuff);
            snprintf((char *)wbuff, sizeof(wbuff), "%lu", leftsize);
            res.add("Content-Length", (char *)wbuff);
            guest->Write(this, wbuff, res.getstring(wbuff));
        } else {
            HttpResHeader res(H416);
            snprintf((char *)wbuff, sizeof(wbuff), "bytes */%lu", st.st_size);
            res.add("Content-Range", (char *)wbuff);
            guest->Write(this, wbuff, res.getstring(wbuff));
        }
        connect(guest, this);
    } else if (S_ISDIR(st.st_mode)) {
        strcat(filename, "/index.html");
        goto repeat;
    }
    handleEvent = (void (Con::*)(uint32_t))&File::defaultHE;
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}


File* File::getfile(HttpReqHeader &req, Guest* guest) {
    File* exist = dynamic_cast<File *>(queryconnect(guest));
    if (exist != NULL) {
        exist->clean();
    }
    return new File(req, guest);
}


int File::showerrinfo(int ret, const char* s) {
    if (ret < 0 && errno != EAGAIN) {
        LOGE("%s: %s\n", s, strerror(errno));
        return 1;
    }
    return 0;
}

void File::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    Guest *guest = dynamic_cast<Guest *>(queryconnect(this));
    if (guest == NULL) {
        clean();
        return;
    }
    if (events & EPOLLIN) {
        if (leftsize == 0) {
            clean();
            return;
        }
        int len = guest->bufleft()<leftsize ? guest->bufleft() : leftsize;
        if (len == 0) {
            LOGE("The guest's write buff is full\n");
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        len = read(ffd, wbuff, len);
        if (len <= 0) {
            if (showerrinfo(len, "file read error")) {
                clean();
            }
            return;
        }
        leftsize -= len;
        guest->Write(this, wbuff, len);
    }
    if (events & EPOLLOUT) {
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("file unkown error: %s\n", strerror(errno));
        clean();
    }
}


void File::closeHE(uint32_t events) {
    if (ffd > 0) {
        close(ffd);
    }
    delete this;
}

