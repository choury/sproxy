#include "cgi.h"
#include "net.h"

#include <map>

#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

std::map<std::string, Cgi *> cgimap;

Cgi::Cgi(const char *filename) {
    strcpy(this->filename, filename);
    void *handle = dlopen(filename,RTLD_NOW);
    if(handle == nullptr) {
        LOGE("dlopen failed: %s\n", dlerror());
        throw 0;
    }
    cgifunc *func=(cgifunc *)dlsym(handle,"cgimain");
    if(func == nullptr) {
        LOGE("dlsym failed: %s\n", dlerror());
        throw 0;
    }
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
        LOGE("socketpair failed: %s\n", strerror(errno));
        throw 0;
    }
    if (fork() == 0) { // 子进程
        signal(SIGPIPE, SIG_DFL);
        close(fds[0]);   // 关闭管道的父进程端
        exit(func(fds[1]));
    } else {    // 父进程
        close(fds[1]);   // 关闭管道的子进程端
        /* 现在可在fd[0]中读写数据 */
        fd=fds[0];
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n",strerror(errno));
            throw 0;
        }
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        handleEvent=(void (Con::*)(uint32_t))&Cgi::defaultHE;
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    }
    cgimap[filename] = this;
}

Cgi::~Cgi() {
    cgimap.erase(filename);
}


int Cgi::showerrinfo(int ret, const char* s) {
    if(ret < 0) {
        if(errno != EAGAIN) {
            LOGE("%s: %s\n",s,strerror(errno));
        } else {
            return 0;
        }
    }
    return 1;
}


void Cgi::InProc() {
    Guest *guest;
    ssize_t len = 0;
    CGI_Header *header = (CGI_Header *)cgi_buff;
    try{
        switch (status) {
        case WaitHeadr:
            len = sizeof(CGI_Header) - cgi_getlen;
            if (len == 0) {
                status = WaitBody;
                break;
            }
            len = read(fd, cgi_buff + cgi_getlen, len);
            if (len <= 0) {
                if (showerrinfo(len, "cgi read")) {
                    clean(this, INTERNAL_ERR);
                }
                return;
            }
            cgi_getlen += len;
            break;
        case WaitBody:
            len = ntohs(header->contentLength) + sizeof(CGI_Header) - cgi_getlen;
            if (len == 0) {
                switch (header->type) {
                case CGI_RESPONSE:
                    status = HandleRes;
                    break;
                case CGI_DATA:
                    status = HandleData;
                    break;
                default:
                    LOGE("cgi unkown type: %d\n", header->type);
                    clean(this, INTERNAL_ERR);
                    return;
                }
                break;
            }
            len = read(fd, cgi_buff + cgi_getlen, len);
            if (len <= 0) {
                if (showerrinfo(len, "cgi read")) {
                    clean(this, INTERNAL_ERR);
                }
                return;
            }
            cgi_getlen += len;
            break;
        case  HandleRes: {
            HttpResHeader res(header);
            if (res.get("content-length") == nullptr) {
                res.add("Transfer-Encoding", "chunked");
            }
            guest = idmap.at(res.id);
            guest->Response(this, res);
            status = WaitHeadr;
            cgi_getlen = 0;
            break;
        }
        case HandleData:
            cgi_outlen = sizeof(CGI_Header);
            status = HandleLeft;
        case HandleLeft:
            guest = idmap.at(ntohl(header->requestId));
            len = guest->bufleft(this);
            if (len <= 0) {
                LOGE("The guest's write buff is full\n");
                guest->wait(this);
                return;
            }
            len = Min(len, cgi_getlen - cgi_outlen);
            len = guest->Write(this, cgi_buff + cgi_outlen, len);
            cgi_outlen += len;
            if (cgi_outlen == cgi_getlen) {
                status = WaitHeadr;
                cgi_getlen = 0;
            }
            if (cgi_outlen == sizeof(CGI_Header)) {
                idmap.erase(guest);
            }
            break;
        }
    }catch(...){
        status = WaitHeadr;
        cgi_getlen = 0;
    }
    InProc();
}


void Cgi::defaultHE(uint32_t events) {
    if (events & EPOLLIN){
        InProc();
    }
    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "host write error")) {
                    clean(this, WRITE_ERR);
                }
                return;
            }
            for(auto i: waitlist){
                i->writedcb(this);
            }
            waitlist.clear();
        }
        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("cgi unkown error: %s\n",strerror(errno));
        clean(this, INTERNAL_ERR);
    }
}

void Cgi::clean(Peer *who, uint32_t errcode) {
    if(who == this) {
        return Peer::clean(who, errcode);
    }
    Guest *guest = dynamic_cast<Guest *>(who);
    idmap.erase(guest);
    disconnect(guest, this);
    waitlist.erase(guest);
}


void Cgi::closeHE(uint32_t events){
    delete this;
}


void Cgi::Request(HttpReqHeader& req, Guest* guest){
    connect(guest, this);
    req.id = curid++;
    writelen += req.getcgi(wbuff + writelen);
    idmap.insert(guest, req.id);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}

void Cgi::wait(Peer *who) {
    waitlist.insert(who);
}


Cgi *Cgi::getcgi(HttpReqHeader &req, Guest *guest){
    Cgi *cgi = nullptr;
    if(cgimap.count(req.filename)){
        cgi = cgimap[req.filename];
    }else{
        cgi = new Cgi(req.filename);
    }
    cgi->Request(req, guest);
    return cgi;
}

int cgi_write(int fd, uint32_t id, const void *buff, size_t len) {
    CGI_Header header;
    do{
        size_t writelen = len > CGI_LEN_MAX ? CGI_LEN_MAX:len;
        header.type = CGI_DATA;
        header.contentLength = htons(writelen);
        header.requestId = htonl(id);
        int ret = write(fd, &header, sizeof(header));
        if(ret != sizeof(header))
            return -1;
        ret = write(fd, buff, writelen);
        if(ret <= 0){
            return ret;
        }
        len -= ret;
        buff = (char *)buff + ret;
    }while(len);
    return len;
}


