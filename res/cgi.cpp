#include "cgi.h"
#include "req/requester.h"
#include "misc/net.h"
#include "misc/strategy.h"

//#include <map>
#include <sstream>

//#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
//#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <assert.h>
#include <libgen.h>


using std::string;
static std::map<std::string, Cgi *> cgimap;

Cgi::Cgi(HttpReqHeader* req) {
    snprintf(filename, sizeof(filename), "%s", req->filename.c_str());
    HttpResHeader* res = nullptr;
    cgifunc *func = nullptr;
    int fds[2]= {0},flags;
    void *handle = dlopen(filename, RTLD_NOW);
    if(handle == nullptr) {
        LOGE("dlopen failed: %s\n", dlerror());
        res = new HttpResHeader(H404);
        goto err;
    }
    func=(cgifunc *)dlsym(handle,"cgimain");
    if(func == nullptr) {
        LOGE("dlsym failed: %s\n", dlerror());
        res = new HttpResHeader(H500);
        goto err;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
        LOGE("socketpair failed: %s\n", strerror(errno));
        res = new HttpResHeader(H500);
        goto err;
    }
    fd=fds[0];

    if (fork() == 0) { // 子进程
        struct rlimit limits;
        if(getrlimit(RLIMIT_NOFILE, &limits)) {
            LOGE("getrlimit failed: %s\n", strerror(errno));
            exit(-1);
        }
        for(int i = 3; i< (int)limits.rlim_cur; i++){
            if(i == fds[1]){
                continue;
            }
            close(i);
        }
        signal(SIGPIPE, SIG_DFL);
        change_process_name(basename(filename));
        exit(func(fds[1]));
    }
    // 父进程
    dlclose(handle);
    close(fds[1]);   // 关闭管道的子进程端
    /* 现在可在fd[0]中读写数据 */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        LOGE("fcntl error:%s\n", strerror(errno));
        res = new HttpResHeader(H500);
        goto err;
    }
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    handleEvent=(void (Con::*)(uint32_t))&Cgi::defaultHE;
    updateEpoll(EPOLLIN);

    cgimap[filename] = this;
    return;
err:
    if(handle) {
        dlclose(handle);
    }
    if(fd) {
        close(fd);
    }
    res->index = req->index;
    req->src->response(res);
    throw 0;
}

Cgi::~Cgi() {
    cgimap.erase(filename);
}

int32_t Cgi::bufleft(void*) {
    return 1024*1024 - buffer.length;
}

ssize_t Cgi::Send(void *buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    size = size > CGI_LEN_MAX ? CGI_LEN_MAX : size;
    CGI_Header *header = (CGI_Header *)p_move(buff, -(char)sizeof(CGI_Header));
    header->type = CGI_DATA;
    header->flag = size ? 0: CGI_FLAG_END;
    header->requestId = htonl(id);
    header->contentLength = htons(size);
    buffer.push(header, size+sizeof(CGI_Header));
    updateEpoll(events | EPOLLOUT);
    return size;
}


/*
 * void Cgi::SendFrame(CGI_Header *header, size_t len)
 * {
 *    write_block wb={header, len, 0};
 *    write_list.push_back(wb);
 *
 *    struct epoll_event event;
 *    event.data.ptr = this;
 *    event.events = EPOLLIN | EPOLLOUT;
 *    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
 * }*/


void Cgi::InProc() {
    CGI_Header *header = (CGI_Header *)cgi_buff;
    uint32_t cgi_id = ntohl(header->requestId);
    switch (cgistage) {
    case Status::WaitHeadr:{
        int len = sizeof(CGI_Header) - cgi_getlen;
        if (len == 0) {
            cgistage = Status::WaitBody;
            break;
        }
        len = read(fd, cgi_buff + cgi_getlen, len);
        if (len <= 0) {
            if (showerrinfo(len, "cgi read")) {
                deleteLater(READ_ERR);
            }
            return;
        }
        cgi_getlen += len;
        break;
    }
    case Status::WaitBody:{
        int len = ntohs(header->contentLength) + sizeof(CGI_Header) - cgi_getlen;
        if (len == 0) {
            if(statusmap.count(cgi_id) == 0) {
                cgistage = Status::WaitHeadr;
                cgi_getlen = 0;
                break;
            }
            switch (header->type) {
            case CGI_RESPONSE:
                cgistage = Status::HandleRes;
                break;
            case CGI_DATA:
                cgistage = Status::HandleData;
                break;
            case CGI_VALUE:
                cgistage = Status::HandleValue;
                break;
            default:
                LOGE("cgi unkown type: %d\n", header->type);
                cgistage = Status::WaitHeadr;
                cgi_getlen = 0;
                break;
            }
            break;
        }
        len = read(fd, cgi_buff + cgi_getlen, len);
        if (len <= 0 && showerrinfo(len, "cgi read")) {
            deleteLater(READ_ERR);
            return;
        }
        cgi_getlen += len;
        break;
    }
    case Status::HandleRes: {
        HttpResHeader* res = new HttpResHeader(header);
        if (!res->no_body() && res->get("content-length") == nullptr) {
            res->add("Transfer-Encoding", "chunked");
        }
        CgiStatus &status = statusmap.at(cgi_id);
        res->index = status.req_index;
        status.req_ptr->response(res);
        cgistage = Status::WaitHeadr;
        cgi_getlen = 0;
        break;
    }
    case Status::HandleValue: {
        CgiStatus& status = statusmap.at(cgi_id);
        CGI_NameValue *nv = (CGI_NameValue *)(header+1);
        uint8_t flag = 0;
        switch(ntohl(nv->name)) {
        case CGI_NAME_BUFFLEFT: {
            CGI_Header* header_back = (CGI_Header*)p_malloc(sizeof(CGI_Header) + sizeof(CGI_NameValue) + sizeof(uint32_t));
            memcpy(header_back, header, sizeof(CGI_Header));
            header_back->flag = 0;
            header_back->contentLength = htons(sizeof(CGI_NameValue) + sizeof(uint32_t));
            CGI_NameValue* nv_back = (CGI_NameValue *)(header_back+1);
            nv_back->name = htonl(CGI_NAME_BUFFLEFT);
            set32(nv_back->value, htonl(status.req_ptr->bufleft(status.req_index)));
            buffer.push(header_back, sizeof(CGI_Header) + ntohs(header_back->contentLength));
            break;
        }
        case CGI_NAME_STRATEGYGET: {
            if(!checkauth(status.req_ptr->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            auto smap = getallstrategy();
            for(auto i: smap) {
                //"name value\0"
                size_t value_len = sizeof(CGI_NameValue) + i.first.length() + i.second.length() + 2;
                CGI_Header* header_back = (CGI_Header*)p_malloc(sizeof(CGI_Header) + value_len);
                memcpy(header_back, header, sizeof(CGI_Header));
                header_back->flag = 0;
                header_back->contentLength = htons(value_len);
                CGI_NameValue* nv_back = (CGI_NameValue *)(header_back+1);
                nv_back->name = htonl(CGI_NAME_STRATEGYGET);
                sprintf((char *)nv_back->value, "%s %s", i.first.c_str(), i.second.c_str());
                buffer.push(header_back, sizeof(CGI_Header) + value_len);
            }
            break;
        }
        case CGI_NAME_STRATEGYADD:{
            if(!checkauth(status.req_ptr->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            char site[DOMAINLIMIT];
            char strategy[20];
            sscanf((char*)nv->value, "%s %s", site, strategy);
            if(addstrategy(site, strategy) == false){
                LOG("[CGI] addstrategy %s (%s)\n", site, strategy);
                flag = CGI_FLAG_ERROR;
            }
            break;
        }
        case CGI_NAME_STRATEGYDEL:{
            if(!checkauth(status.req_ptr->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            if(delstrategy((char *)nv->value) == false){
                LOG("[CGI] delstrategy %s\n", (char *)nv->value);
                flag = CGI_FLAG_ERROR;
            }
            break;
        }
        case CGI_NAME_GETPROXY:{
            if(!checkauth(status.req_ptr->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            char proxy[DOMAINLIMIT];
            int len = getproxy(proxy, sizeof(proxy));
            CGI_Header* header_back = (CGI_Header*)p_malloc(sizeof(CGI_Header) + sizeof(CGI_NameValue) + len);
            memcpy(header_back, header, sizeof(CGI_Header));
            header_back->flag = 0;
            header_back->contentLength = htons(sizeof(CGI_NameValue) + len);
            CGI_NameValue* nv_back = (CGI_NameValue *)(header_back+1);
            nv_back->name = htonl(CGI_NAME_GETPROXY);
            memcpy(nv_back->value, proxy, len);
            buffer.push(header_back, sizeof(CGI_Header) + ntohs(header_back->contentLength));
            break;
        }
        case CGI_NAME_SETPROXY:{
            if(!checkauth(status.req_ptr->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            if(setproxy((char *)nv->value)){
                LOG("[CGI] switch %s\n", (char *)nv->value);
                flag = CGI_FLAG_ERROR;
            }
            break;
        }
        case CGI_NAME_LOGIN:{
            if(strcmp(auth_string, (char *)nv->value)){
                flag = CGI_FLAG_ERROR;
            }else{
                LOG("[CGI] %s login\n", status.req_ptr->getip());
                addauth(status.req_ptr->getip());
            }
            break;
        }
        default:
            break;
        }
        CGI_Header* header_end = (CGI_Header*)p_malloc(sizeof(CGI_Header));
        memcpy(header_end, header, sizeof(CGI_Header));
        header_end->contentLength = 0;
        header_end->flag = flag | CGI_FLAG_END;
        buffer.push(header_end, sizeof(CGI_Header));
        updateEpoll(events | EPOLLOUT);
        cgistage = Status::WaitHeadr;
        cgi_getlen = 0;
        break;
    }
    case Status::HandleData:
        cgi_outlen = sizeof(CGI_Header);
        cgistage = Status::HandleLeft;
    case Status::HandleLeft:{
        CgiStatus& status = statusmap.at(cgi_id);
        if (cgi_outlen == cgi_getlen) {
            cgistage = Status::WaitHeadr;
            cgi_getlen = 0;
        }else{
            int len = status.req_ptr->bufleft(status.req_index);
            if (len <= 0) {
                LOGE("The requester's write buff is full\n");
                updateEpoll(0);
                return;
            }
            len = Min(len, cgi_getlen - cgi_outlen);
            len = status.req_ptr->Send((const char *)cgi_buff + cgi_outlen, len, status.req_index);
            cgi_outlen += len;
        }
        if (header->flag & CGI_FLAG_END) {
            status.req_ptr->finish(NOERROR, status.req_index);
            statusmap.erase(cgi_id);
        }
        break;
    }
    default:
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
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLIN) {
        InProc();
    }
    if (events & EPOLLOUT) {
        int ret = buffer.Write([this](const void * buff, size_t size){
            return Write(buff, size);
        });
        if(ret < 0 && showerrinfo(ret, "cgi write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(buffer.length == 0){
            updateEpoll(EPOLLIN);
        }
        for(auto i: statusmap) {
            CgiStatus& status = i.second;
            status.req_ptr->writedcb(status.req_index);
        }
    }
}

void Cgi::finish(uint32_t errcode, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    Peer::Send((const void*)nullptr, 0, index);
    if(errcode){
        statusmap.erase(id);
    }
}

void Cgi::deleteLater(uint32_t errcode){
    for(auto i: statusmap) {
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void* Cgi::request(HttpReqHeader* req) {
    uint32_t cgi_id = curid++;
    statusmap[cgi_id] = CgiStatus {req->src, req->index};
    CGI_Header *header = req->getcgi(cgi_id);
    buffer.push(header, sizeof(CGI_Header) + ntohs(header->contentLength));
    updateEpoll(events | EPOLLOUT);
    delete req;
    return reinterpret_cast<void*>(cgi_id);
}

void Cgi::dump_stat(){
    LOG("Cgi %p %s, id=%d:\n", this, filename, curid);
    for(auto i: statusmap){
        LOG("%d: %p, %p", i.first, i.second.req_ptr, i.second.req_index);
    }
}



Cgi* Cgi::getcgi(HttpReqHeader* req) {
    if(cgimap.count(req->filename)) {
        return cgimap[req->filename];
    } else {
        try {
            return new Cgi(req);
        } catch(...) {
            return nullptr;
        }
    }
}


void flushcgi() {
    for(auto i:cgimap) {
        i.second->deleteLater(PEER_LOST_ERR);
    }
}


void addcookie(HttpResHeader &res, const Cookie &cookie) {
    std::stringstream cookiestream;
    cookiestream << cookie.name <<'='<<cookie.value;
    if(cookie.path) {
        cookiestream << "; path="<< cookie.path;
    }
    if(cookie.domain) {
        cookiestream << "; domain="<< cookie.domain;
    }
    if(cookie.maxage) {
        cookiestream << "; max-age="<< cookie.maxage;
    }
    res.cookies.insert(cookiestream.str());
}

int cgi_response(int fd, const HttpResHeader &res, uint32_t cgi_id) {
    CGI_Header *header = res.getcgi(cgi_id);
    int ret = write(fd, header, sizeof(CGI_Header) + ntohs(header->contentLength));
    p_free(header);
    return ret;
}

std::map< string, string > getparamsmap(const char* param) {
    return getparamsmap(param, strlen(param));
}


std::map< string, string > getparamsmap(const char *param, size_t len) {
    std::map< string, string > params;
    if(len == 0) {
        return params;
    }
    char paramsbuff[URLLIMIT];
    URLDecode(paramsbuff, param, len);
    char *p=paramsbuff;
    if(*p) {
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


int cgi_write(int fd, uint32_t id, const void *buff, size_t len) {
    CGI_Header header;
    size_t left = len;
    do {
        size_t writelen = left > CGI_LEN_MAX ? CGI_LEN_MAX:left;
        header.type = CGI_DATA;
        header.flag = (len == 0)? CGI_FLAG_END:0;
        header.contentLength = htons(writelen);
        header.requestId = htonl(id);
        int ret = write(fd, &header, sizeof(header));
        if(ret != sizeof(header))
            return -1;
        ret = write(fd, buff, writelen);
        if(ret <= 0) {
            return ret;
        }
        left -= ret;
        buff = (char *)buff + ret;
    } while(left);
    return len;
}

int cgi_query(int fd, uint32_t id, int name) {
    CGI_Header header;
    header.type = CGI_VALUE;
    header.flag = CGI_FLAG_END;
    header.contentLength = htons(sizeof(CGI_NameValue));
    header.requestId = htonl(id);
    int ret = write(fd, &header, sizeof(header));
    if(ret != sizeof(header))
        return -1;
    CGI_NameValue nv;
    nv.name = htonl(name);

    ret = write(fd, &nv, sizeof(nv));
    if(ret != sizeof(nv))
        return -1;
    return 0;
}


int cgi_set(int fd, uint32_t id, int name, const void* value, size_t len) {
    size_t size = sizeof(CGI_Header) + sizeof(CGI_NameValue) + len;
    CGI_Header* header = (CGI_Header*)malloc(size);
    header->type = CGI_VALUE;
    header->flag = CGI_FLAG_END;
    header->contentLength = htons(sizeof(CGI_NameValue) + len);
    header->requestId = htonl(id);

    CGI_NameValue *nv = (CGI_NameValue* )(header + 1);
    nv->name = htonl(name);
    memcpy(nv->value, value, len);
    int ret = write(fd, header, size);
    free(header);
    if(ret != (ssize_t)size)
        return -1;
    return 0;
}
