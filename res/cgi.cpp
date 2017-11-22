#include "cgi.h"
#include "req/requester.h"
#include "misc/net.h"
#include "misc/strategy.h"
#include "misc/util.h"

#include <sstream>

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>


using std::string;
static std::map<std::string, Cgi *> cgimap;

#define CGI_RETURN_DLOPEN_FAILED       1
#define CGI_RETURN_DLSYM_FAILED        2

Cgi::Cgi(const char* fname, int sv[2]) {
    snprintf(filename, sizeof(filename), "%s", fname);
    if (fork() == 0) { // 子进程
        void *handle = dlopen(fname, RTLD_NOW);
        if(handle == nullptr) {
            LOGE("dlopen failed: %s\n", dlerror());
            exit(-1);
        }
        cgifunc* func=(cgifunc *)dlsym(handle,"cgimain");
        if(func == nullptr) {
            LOGE("dlsym failed: %s\n", dlerror());
            exit(-1);
        }
        struct rlimit limits;
        if(getrlimit(RLIMIT_NOFILE, &limits)) {
            LOGE("getrlimit failed: %s\n", strerror(errno));
            exit(-1);
        }
        for(int i = 3; i< (int)limits.rlim_cur; i++){
            if(i == sv[1]){
                continue;
            }
            close(i);
        }
        signal(SIGPIPE, SIG_DFL);
        change_process_name(basename(filename));
        exit(func(sv[1]));
    }
    // 父进程
    close(sv[1]);   // 关闭管道的子进程端
    /* 现在可在fd[0]中读写数据 */
    fd = sv[0];
    handleEvent=(void (Con::*)(uint32_t))&Cgi::defaultHE;
    updateEpoll(EPOLLIN);
    cgimap[filename] = this;
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


void Cgi::InProc() {
    CGI_Header *header = (CGI_Header *)cgi_buff;
begin:
    uint32_t cgi_id = ntohl(header->requestId);
    switch (cgistage) {
    case Status::WaitHeadr:{
        int len = sizeof(CGI_Header) - cgi_getlen;
        if (len == 0) {
            assert(ntohs(header->contentLength) <= CGI_LEN_MAX);
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
        if (len <= 0){
            if(showerrinfo(len, "cgi read")) {
                deleteLater(READ_ERR);
            }
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
        HttpReqHeader* req = statusmap.at(cgi_id);
        res->index = req->index;
        req->src->response(res);
        req->flags |= HTTP_RESPONED_F;
        cgistage = Status::WaitHeadr;
        cgi_getlen = 0;
        break;
    }
    case Status::HandleValue: {
        HttpReqHeader* req = statusmap.at(cgi_id);
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
            set32(nv_back->value, htonl(req->src->bufleft(req->index)));
            buffer.push(header_back, sizeof(CGI_Header) + ntohs(header_back->contentLength));
            break;
        }
        case CGI_NAME_STRATEGYGET: {
            if(!checkauth(req->src->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            auto slist = getallstrategy();
            for(auto i: slist) {
                auto host = std::get<0>(i);
                if(host == ""){
                   host = "_";
                }
                auto strategy =  std::get<1>(i);
                auto ext = std::get<2>(i);
                //"host strategy ext\0"
                size_t value_len = sizeof(CGI_NameValue) + host.length() + strategy.length() + ext.length() + 3;
                CGI_Header* header_back = (CGI_Header*)p_malloc(sizeof(CGI_Header) + value_len);
                memcpy(header_back, header, sizeof(CGI_Header));
                header_back->flag = 0;
                header_back->contentLength = htons(value_len);
                CGI_NameValue* nv_back = (CGI_NameValue *)(header_back+1);
                nv_back->name = htonl(CGI_NAME_STRATEGYGET);
                sprintf((char *)nv_back->value, "%s %s %s", host.c_str(), strategy.c_str(), ext.c_str());
                buffer.push(header_back, sizeof(CGI_Header) + value_len);
            }
            break;
        }
        case CGI_NAME_STRATEGYADD:{
            if(!checkauth(req->src->getip())){
                flag = CGI_FLAG_ERROR;
                break;
            }
            char site[DOMAINLIMIT];
            char strategy[20];
            sscanf((char*)nv->value, "%s %s", site, strategy);
            if(addstrategy(site, strategy, "") == false){
                LOG("[CGI] addstrategy %s (%s)\n", site, strategy);
                flag = CGI_FLAG_ERROR;
            }
            break;
        }
        case CGI_NAME_STRATEGYDEL:{
            if(!checkauth(req->src->getip())){
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
            if(!checkauth(req->src->getip())){
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
            if(!checkauth(req->src->getip())){
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
                LOG("[CGI] %s login\n", req->src->getip());
                addauth(req->src->getip());
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
        HttpReqHeader* req = statusmap.at(cgi_id);
        if (cgi_outlen == cgi_getlen) {
            cgistage = Status::WaitHeadr;
            cgi_getlen = 0;
        }else{
            int len = req->src->bufleft(req->index);
            if (len <= 0) {
                LOGE("The requester's write buff is full\n");
                updateEpoll(0);
                return;
            }
            len = Min(len, cgi_getlen - cgi_outlen);
            len = req->src->Send((const char *)cgi_buff + cgi_outlen, len, req->index);
            cgi_outlen += len;
        }
        if (header->flag & CGI_FLAG_END) {
            req->src->finish(NOERROR | DISCONNECT_FLAG, req->index);
            statusmap.erase(cgi_id);
            delete req;
        }
        break;
    }
    default:
        break;
    }
    goto begin;
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

    if (events & EPOLLOUT) {
        int ret = buffer.Write([this](const void * buff, size_t size){
            return Write(buff, size);
        });
        if(ret < 0 && showerrinfo(ret, "cgi write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        for(auto i: statusmap) {
            i.second->src->writedcb(i.second->index);
        }
        if(buffer.length == 0){
            updateEpoll(this->events & ~EPOLLOUT);
        }
    }
    
    if (events & EPOLLIN) {
        InProc();
    }
}

bool Cgi::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    Peer::Send((const void*)nullptr, 0, index);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode){
        delete statusmap[id];
        statusmap.erase(id);
        return false;
    }
    return true;
}

void Cgi::deleteLater(uint32_t errcode){
    for(auto i: statusmap) {
        if((i.second->flags & HTTP_RESPONED_F) == 0){
            HttpResHeader* res = new HttpResHeader(H503);
            res->index = i.second->index;
            i.second->src->response(res);
        }
        i.second->src->finish(errcode, i.second->index);
        delete i.second;
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void* Cgi::request(HttpReqHeader* req) {
    uint32_t cgi_id = curid++;
    statusmap[cgi_id] = req;
    CGI_Header *header = req->getcgi(cgi_id);
    buffer.push(header, sizeof(CGI_Header) + ntohs(header->contentLength));
    updateEpoll(events | EPOLLOUT);
    return reinterpret_cast<void*>(cgi_id);
}

void Cgi::dump_stat(){
    LOG("Cgi %p %s, id=%d:\n", this, filename, curid);
    for(auto i: statusmap){
        LOG("%d: %p, %p", i.first, i.second->src, i.second->index);
    }
}



Cgi* getcgi(HttpReqHeader* req, const char* filename){
    if(cgimap.count(filename)) {
        return cgimap[filename];
    } else {
        int fds[2] = {0}, flags;
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
            LOGE("socketpair failed: %s\n", strerror(errno));
            goto err;
        }
        flags = fcntl(fds[0], F_GETFL, 0);
        if (flags < 0) {
            LOGE("fcntl error:%s\n", strerror(errno));
            goto err;
        }
        fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);
        return new Cgi(filename, fds);
err:
        if(fds[0]){
            close(fds[0]);
            close(fds[1]);
        }
        HttpResHeader* res = new HttpResHeader(H500);
        res->index = req->index;
        req->src->response(res);
        return nullptr;
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
