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

ssize_t Cgi::Write(const void *buff, size_t size, Peer* who, uint32_t id) {
    Guest *guest = dynamic_cast<Guest *>(who);
    if(idmap.count(std::make_pair(guest, id))){
        uint32_t id = idmap.at(std::make_pair(guest, id));
        CGI_Header header;
        memset(&header, 0, sizeof(header));
        size = Min(size, bufleft(guest));
        header.type = CGI_DATA;
        header.requestId = htonl(id);
        header.contentLength = htons(size);
        SendFrame(&header, 0);
        return Peer::Write(buff, size, this);
    }else{
        who->clean(PEER_LOST_ERR, this, id);
        return -1;
    }
}

CGI_Header* Cgi::SendFrame(const CGI_Header *header, size_t addlen)
{
    size_t len = sizeof(CGI_Header) + addlen;
    CGI_Header *frame = (CGI_Header *)malloc(len);
    memcpy(frame, header, len);
    framequeue.push_back(frame);
    
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return frame;
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
                    throw 0;
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
            HttpResHeader res(header);
            if (res.get("content-length") == nullptr) {
                res.add("Transfer-Encoding", "chunked");
            }
            session = idmap.at(res.cgi_id);
            guest = session.first;
            res.http_id = session.second;
            guest->Response(res, this);
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
            SendFrame(header, ntohs(header->contentLength));
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
            len = guest->Write(cgi_buff + cgi_outlen, len, this, session.second);
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
    }catch(...){
        status = WaitHeadr;
        cgi_getlen = 0;
    }
    InProc();
}

int Cgi::OutProc() {
    if (dataleft && writelen){ //先将data帧的数据写完
        int len = Min(writelen, dataleft);
        int ret = Peer::Write(wbuff, len);
        if(ret>0){
            memmove(wbuff, wbuff + ret, writelen - ret);
            writelen -= ret;
            dataleft -= ret;
            if(ret != len){
                return 1;
            }
        }else { 
            return ret;
        }
    }
    if(dataleft == 0 && !framequeue.empty()){  //data帧已写完
        do{
            CGI_Header *header = framequeue.front();
            size_t framewritelen;
            if(header->type == CGI_DATA){
                framewritelen = sizeof(CGI_Header);
            }else{
                framewritelen = ntohs(header->contentLength) + sizeof(CGI_Header);
            }
            frameleft = frameleft?frameleft:framewritelen;
            int ret = Peer::Write((char *)header+framewritelen-frameleft, frameleft);
            if(ret>0){
                frameleft -= ret;
                if(frameleft == 0 ){
                    size_t len = ntohs(header->contentLength);
                    framequeue.pop_front();
                    if(header->type == CGI_DATA && len){
                        dataleft = len;
                        free(header);
                        return 1;
                    }
                    free(header);
                }
            }else{
                return ret;
            }
        }while(!framequeue.empty());
    }
    return (dataleft == 0 && framequeue.empty()) ? 2 : 1;
}



void Cgi::defaultHE(uint32_t events) {
    if (events & EPOLLIN){
        InProc();
    }
    if (events & EPOLLOUT) {
        int ret = OutProc();
        if(ret){ 
            for(auto i: waitlist){
                i->writedcb(this);
            }
            waitlist.clear();
        }else if(ret <= 0 && showerrinfo(ret, "cgi write error")) {
            clean(WRITE_ERR, this);
            return;
        }

        if (ret == 2) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("cgi unkown error: %s\n",strerror(errno));
        clean(INTERNAL_ERR, this);
    }
}

void Cgi::clean(uint32_t errcode, Peer* who, uint32_t id) {
    if(who == this) {
        return Peer::clean(errcode, this);
    }
    Guest *guest = dynamic_cast<Guest *>(who);
    idmap.erase(std::make_pair(guest, id));
    disconnect(guest, this);
    waitlist.erase(guest);
}


void Cgi::closeHE(uint32_t events){
    delete this;
}


void Cgi::Request(HttpReqHeader& req, Guest* guest){
    connect(guest, this);
    req.cgi_id = curid++;
    idmap.insert(std::make_pair(guest, req.http_id), req.cgi_id);
    char buff[CGI_LEN_MAX];
    SendFrame((CGI_Header *)buff, req.getcgi(buff));
}

void Cgi::wait(Peer *who) {
    waitlist.insert(who);
}


Cgi *Cgi::getcgi(HttpReqHeader &req, Guest *guest){
    Cgi *cgi = nullptr;
    try{
        if(cgimap.count(req.filename)){
            cgi = cgimap[req.filename];
        }else{
            cgi = new Cgi(req.filename);
        }
    }catch(...){
        HttpResHeader res(H500);
        res.http_id = req.http_id;
        guest->Response(res, nullptr);
        throw 0;
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


