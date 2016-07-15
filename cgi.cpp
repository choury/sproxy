#include "cgi.h"
#include "guest.h"
#include "net.h"

#include <map>
#include <sstream>

#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

using std::string;
std::map<std::string, Cgi *> cgimap;

Cgi::Cgi(HttpReqHeader& req) {
    const char *errinfo = nullptr;
    cgifunc *func = nullptr;
    int fds[2]={0},flags;
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    void *handle = dlopen(req.filename,RTLD_NOW);
    if(handle == nullptr) {
        LOGE("dlopen failed: %s\n", dlerror());
        errinfo = H404;
        goto err;
    }
    func=(cgifunc *)dlsym(handle,"cgimain");
    if(func == nullptr) {
        LOGE("dlsym failed: %s\n", dlerror());
        errinfo = H500;
        goto err;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
        LOGE("socketpair failed: %m\n");
        errinfo = H500;
        goto err;
    }
    if (fork() == 0) { // 子进程
        signal(SIGPIPE, SIG_DFL);
        close(fds[0]);   // 关闭管道的父进程端
        exit(func(fds[1]));
    } 
    // 父进程
    dlclose(handle);
    close(fds[1]);   // 关闭管道的子进程端
    /* 现在可在fd[0]中读写数据 */
    fd=fds[0];
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        LOGE("fcntl error:%m\n");
        errinfo = H500;
        goto err;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    handleEvent=(void (Con::*)(uint32_t))&Cgi::defaultHE;
    updateEpoll(EPOLLIN);

    snprintf(filename, sizeof(filename), "%s", req.filename);
    cgimap[filename] = this;
    return;
err:
    if(handle){
        dlclose(handle);
    }
    if(fd){
        close(fd);
    }
    HttpResHeader res(errinfo);
    res.http_id = req.http_id;
    guest->response(res);
    throw 0;
}

Cgi::~Cgi() {
    cgimap.erase(filename);
} 

ssize_t Cgi::Write(void *buff, size_t size, Peer* who, uint32_t id) {
    ssize_t ret= Write((const void*)buff, size, who,id);
    free(buff);
    return ret;
}

ssize_t Cgi::Write(const void *buff, size_t size, Peer* who, uint32_t id) {
    Guest *guest = dynamic_cast<Guest *>(who);
    if(idmap.count(std::make_pair(guest, id))){
        uint32_t cgi_id = idmap.at(std::make_pair(guest, id));
        CGI_Header *header = (CGI_Header *)malloc(sizeof(CGI_Header) + size);
        memset(header, 0, sizeof(CGI_Header));
        header->type = CGI_DATA;
        header->requestId = htonl(cgi_id);
        header->contentLength = htons(size);
        memcpy(header+1, buff, size);
        return Peer::Write(header, sizeof(CGI_Header) + size, this);
    }else{
        who->clean(PEER_LOST_ERR, this, id);
        return -1;
    }
}

/*
void Cgi::SendFrame(CGI_Header *header, size_t len)
{
    write_block wb={header, len, 0};
    write_list.push_back(wb);
    
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}*/


int Cgi::showerrinfo(int ret, const char* s) {
    if(ret < 0) {
        if(errno != EAGAIN) {
            LOGE("%s: %m\n",s);
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
    std::pair<Guest *, uint32_t> session;
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
                clean(INTERNAL_ERR, this);
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
            case CGI_VALUE:
                status = HandleValue;
                break;
            default:
                LOGE("cgi unkown type: %d\n", header->type);
                status = WaitHeadr;
                cgi_getlen = 0;
                break;
            }
            break;
        }
        len = read(fd, cgi_buff + cgi_getlen, len);
        if (len <= 0) {
            if (showerrinfo(len, "cgi read")) {
                clean(INTERNAL_ERR, this);
            }
            return;
        }
        cgi_getlen += len;
        break;
    case  HandleRes: {
        HttpResHeader res(header, shared_from_this());
        if (res.get("content-length") == nullptr) {
            res.add("Transfer-Encoding", "chunked");
        }
        session = idmap.at(res.cgi_id);
        guest = session.first;
        res.http_id = session.second;
        guest->response(res);
        status = WaitHeadr;
        cgi_getlen = 0;
        break;
    }
    case HandleValue:
        guest = idmap.at(ntohl(header->requestId)).first;
        if((header->flag & CGI_FLAG_ACK)==0){
            header->flag |= CGI_FLAG_ACK;
            CGI_NameValue *nv = (CGI_NameValue *)(header+1);
            while((char *)(nv+1) - (char*)header <= (int)cgi_getlen){
                switch(ntohl(nv->name)){
                case CGI_NAME_BUFFLEFT:
                    nv->value = htonl(guest->bufleft(this));
                    header->contentLength = htons((char *)(nv+1) - (char*)header);
                    break;
                default:
                    goto send;
                }
                nv++;
            }
        }
send:
        Peer::Write((const void *)header, sizeof(CGI_Header) + ntohs(header->contentLength), this);
        status = WaitHeadr;
        cgi_getlen = 0;
        break;
    case HandleData:
        cgi_outlen = sizeof(CGI_Header);
        status = HandleLeft;
    case HandleLeft:
        session = idmap.at(ntohl(header->requestId));
        guest = session.first;
        len = guest->bufleft(this);
        if (len <= 0) {
            LOGE("The guest's write buff is full\n");
            guest->wait(this);
            return;
        }
        len = Min(len, cgi_getlen - cgi_outlen);
        len = guest->Write((const char *)cgi_buff + cgi_outlen, len, this, session.second);
        cgi_outlen += len;
        if (cgi_outlen == cgi_getlen) {
            status = WaitHeadr;
            cgi_getlen = 0;
        }
        if (cgi_outlen == sizeof(CGI_Header)) {
            idmap.erase(session);
        }
        break;
    }
    InProc();
}

void Cgi::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("cgi unkown error: %s\n", strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }

    if (events & EPOLLIN){
        InProc();
    }
    if (events & EPOLLOUT) {
        int ret = Peer::Write();
        if(ret > 0 && ret != WRITE_NOTHING){
            for(auto i: waitlist){
                i->writedcb(this);
            }
            waitlist.clear();
        }else if(ret <= 0 && showerrinfo(ret, "cgi write error")) {
            clean(WRITE_ERR, this);
            return;
        }
    }
}

void Cgi::clean(uint32_t errcode, Peer* who, uint32_t id) {
    if(who == this) {
        return Peer::clean(errcode, this);
    }
    Guest *guest = dynamic_cast<Guest *>(who);
    idmap.erase(std::make_pair(guest, id));
    waitlist.erase(guest);
}


Ptr Cgi::request(HttpReqHeader& req){
    Guest *guest = dynamic_cast<Guest *>(req.getsrc().get());
    if(guest){
        req.cgi_id = curid++;
        idmap.insert(std::make_pair(guest, req.http_id), req.cgi_id);
        CGI_Header *header = req.getcgi();
        Peer::Write(header, sizeof(CGI_Header) + ntohs(header->contentLength), this);
    }
    return shared_from_this();
}

void Cgi::wait(Peer *who) {
    waitlist.insert(who);
}


Ptr Cgi::getcgi(HttpReqHeader &req){
    if(cgimap.count(req.filename)){
        return cgimap[req.filename]->request(req);
    }else{
        try{
            return (new Cgi(req))->request(req);
        }catch(...){
            return Ptr();
        }
    }
}


void flushcgi() {
    for(auto i:cgimap){
        i.second->clean(NOERROR, i.second);
    }
}


std::map< string, string > getparams(const HttpReqHeader &req) {
    char paramsbuff[URLLIMIT];
    URLDecode(req.path,paramsbuff);
    char *p=paramsbuff;
    while (*p && *++p != '?');
    std::map< string, string > params;
    if(*p++){
        for (; ; p = NULL) {
            char *q = strtok(p, "&");

            if (q == NULL)
                break;

            char* sp = strpbrk(q, "=");
            if (sp) {
                params[string(q, sp - q)] = sp + 1;
            } else {
                params[q] = "";
            }
        }
    }
    return params;
}

std::map<string, string> getcookies(const HttpReqHeader &req) {
    std::map<string, string> cookie;
    for(auto i:req.cookies){
        const char *p = i.c_str();
        const char* sp = strpbrk(p, "=");
        if (sp) {
            cookie[ltrim(string(p, sp - p))] = sp + 1;
        } else {
            cookie[p] = "";
        }
    }
    return cookie;
}

void addcookie(HttpResHeader &res, const Cookie &cookie){
    std::stringstream cookiestream;
    cookiestream << cookie.name <<'='<<cookie.value;
    if(cookie.path){
        cookiestream << "; path="<< cookie.path;
    }
    if(cookie.domain){
        cookiestream << "; domain="<< cookie.domain;
    }
    if(cookie.maxage){
        cookiestream << "; max-age="<< cookie.maxage;
    }
    res.cookies.insert(cookiestream.str());
}

int cgi_response(int fd, const HttpResHeader &res){
    CGI_Header *header = res.getcgi();
    int ret = write(fd, header, sizeof(CGI_Header) + ntohs(header->contentLength));
    free(header);
    return ret;
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


