#include "cgi.h"
#include "req/requester.h"
#include "res/proxy2.h"
#include "prot/netio.h"
#include "misc/net.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"

#include <sstream>

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <signal.h>
#include <sys/resource.h>
#include <errno.h>
#include <assert.h>
#include <libgen.h>
#include <inttypes.h>


using std::string;
static std::map<std::string, Cgi*> cgimap;

#define CGI_RETURN_DLOPEN_FAILED       1
#define CGI_RETURN_DLSYM_FAILED        2

Cgi::Cgi(const char* fname, int sv[2]) {
    snprintf(filename, sizeof(filename), "%s", fname);
    if (fork() == 0) { // 子进程
        void *handle = dlopen(fname, RTLD_NOW);
        if(handle == nullptr) {
            LOGE("[CGI] %s dlopen failed: %s\n", fname, dlerror());
            exit(-CGI_RETURN_DLOPEN_FAILED);
        }
        LOGD(DFILE, "<cgi> dlopen: %s\n", fname);
        cgifunc* func=(cgifunc *)dlsym(handle,"cgimain");
        if(func == nullptr) {
            LOGE("[CGI] %s dlsym failed: %s\n", fname, dlerror());
            exit(-CGI_RETURN_DLSYM_FAILED);
        }
        struct rlimit limits;
        if(getrlimit(RLIMIT_NOFILE, &limits)) {
            LOGE("[CGI] %s getrlimit failed: %s\n", fname, strerror(errno));
            exit(-1);
        }
        for(int i = 3; i< (int)limits.rlim_cur; i++){
            if(i == sv[1]){
                continue;
            }
            close(i);
        }
        setenv("ADMIN_SOCK", opt.socket, 1);
        signal(SIGPIPE, SIG_DFL);
        change_process_name(basename(filename));
        LOGD(DFILE, "<cgi> [%s] jump to cgi main\n", basename(filename));
        exit(func(sv[1]));
    }
    // 父进程
    close(sv[1]);   // 关闭管道的子进程端
    /* 现在可在fd[0]中读写数据 */
    rwer = new StreamRWer(sv[0], nullptr, [this](int ret, int code){
        LOGE("[CGI] %s error: %d/%d\n", basename(filename), ret, code);
        deleteLater(ret);
    });
    rwer->SetReadCB(std::bind(&Cgi::readHE, this, _1));
    cgimap[filename] = this;
}

void Cgi::evictMe(){
    if(cgimap.count(filename) == 0 || cgimap[filename] != this){
        return;
    }
    cgimap.erase(filename);
}

void Cgi::Clean(uint32_t id, CgiStatus& status) {
    LOG("<cgi> [%s] %" PRIu32" abort\n", basename(filename), id);
    if(status.res == nullptr){
        status.req->response(new HttpRes(new HttpResHeader(H500), "[[cgi failed]]\n"));
    }else {
        status.res->trigger(Channel::CHANNEL_ABORT);
    }
    statusmap.erase(id);
}

Cgi::~Cgi() {
}

void Cgi::Send(uint32_t id, void *buff, size_t size) {
    LOGD(DFILE, "<cgi> [%s] stream %" PRIu32 " send: %zd\n", basename(filename), id, size);
    assert(statusmap.count(id));
    size = size > CGI_LEN_MAX ? CGI_LEN_MAX : size;
    CGI_Header *header = (CGI_Header *)p_move(buff, -(char)sizeof(CGI_Header));
    header->type = CGI_DATA;
    header->flag = size ? 0: CGI_FLAG_END;
    header->requestId = htonl(id);
    header->contentLength = htons(size);
    rwer->buffer_insert(rwer->buffer_end(), write_block{header, size+sizeof(CGI_Header), 0});
}


void Cgi::readHE(size_t len) {
    if (len < sizeof(CGI_Header)) {
        return;
    }
begin:
    const CGI_Header *header = (const CGI_Header *)rwer->rdata();
    size_t size = ntohs(header->contentLength) + sizeof(CGI_Header);
    if(len < size){
        return;
    }
    uint32_t id = ntohl(header->requestId);
    bool consumed = false;
    if(statusmap.count(id)) {
        CgiStatus& status = statusmap[id];
        switch (header->type) {
        case CGI_RESPONSE:
            consumed = HandleRes(header, status);
            break;
        case CGI_DATA:
            consumed = HandleData(header, status);
            break;
        case CGI_ERROR:
            consumed = HandleError(header, status);
            break;
        default:
            LOGE("[CGI] %s unknown type: %d\n", basename(filename), header->type);
            consumed = true;
            break;
        }
    }else{
        LOGE("[CGI] %s unknown id: %d, type:%d\n", basename(filename), id, header->type);
        consumed = true;
    }
    if(consumed){
        rwer->consume((const char*)header, size);
        len -= size;
        goto begin;
    }
}

bool Cgi::HandleRes(const CGI_Header *cheader, CgiStatus& status){
    HttpResHeader* header = new HttpResHeader(cheader);
    LOGD(DFILE, "<cgi> [%s] res %" PRIu32 ": %s\n", basename(filename), header->request_id, header->status);
    if (!header->no_body() && header->get("content-length") == nullptr) {
        header->set("transfer-encoding", "chunked");
    }
    status.res = new HttpRes(header, std::bind(&RWer::EatReadData, rwer));
    status.req->response(status.res);
    return true;
}


static void cgi_error(CGI_Header* header, uint32_t id, uint8_t flag){
    header->type = CGI_ERROR;
    header->flag = flag;
    header->contentLength = 0;
    header->requestId = htonl(id);
}

bool Cgi::HandleData(const CGI_Header* header, CgiStatus& status){
    int len = status.res->cap();
    size_t size = ntohs(header->contentLength);
    if (len < (int)size) {
        LOGE("[CGI] The requester's write buff is not enougth(%zu/%d)\n", size, len);
        rwer->delEvents(RW_EVENT::READ);
        return false;
    }

    LOGD(DFILE, "<cgi> [%s] handle %d data %zu\n", basename(filename), htonl(header->requestId), size);
    status.res->send((const char *)(header+1), size);
    if (header->flag & CGI_FLAG_END) {
        uint32_t id = ntohl(header->requestId);
        if(size){
            status.res->send((const void *)nullptr, 0);
        }
        status.res->trigger(Channel::CHANNEL_CLOSED);
        statusmap.erase(id);
    }
    return true;
}

bool Cgi::HandleError(const CGI_Header* header, CgiStatus& status){
    uint32_t id = ntohl(header->requestId);
    LOG("<cgi> [%s] %" PRIu32 " error with %d\n", basename(filename), id, header->flag);
    if(header->flag & CGI_FLAG_ABORT){
        Clean(id, status);
    }
    return true;
}

void Cgi::deleteLater(uint32_t errcode){
    evictMe();
    auto statusmapCopy = statusmap;
    for(auto i: statusmapCopy) {
        Clean(i.first, i.second);
    }
    statusmap.clear();
    return Server::deleteLater(errcode);
}


void Cgi::request(HttpReq* req, Requester* src) {
    uint32_t id = req->header->request_id;
    LOGD(DFILE, "<cgi> [%s] new request: %" PRIu32 "\n", basename(filename), id);
    statusmap[id] = CgiStatus{
        req,
        nullptr,
    };
    req->header->set("X-Real-IP", src->getid());
    req->header->set("X-Authorized",
                     checkauth(src->getid(), req->header->get("Authorization")));
    CGI_Header *header = req->header->getcgi();
    rwer->buffer_insert(rwer->buffer_end(),
                        write_block{header, sizeof(CGI_Header) + ntohs(header->contentLength), 0}
                       );
    req->setHandler([this, id](Channel::signal s){
        if(statusmap.count(id) == 0) {
            LOGE("[CGI] %s stream %" PRIu32 " finished, not found\n", basename(filename), id);
            return;
        }
        LOGD(DFILE, "<cgi> [%s] stream %" PRIu32" finished\n", basename(filename), id);
        if(s == Channel::CHANNEL_SHUTDOWN) {
            Clean(id, statusmap[id]);
        }else {
            statusmap.erase(id);
        }
        size_t len = sizeof(CGI_Header);
        CGI_Header *header = (CGI_Header *)p_malloc(len);
        cgi_error(header, id, CGI_FLAG_ABORT);
        rwer->buffer_insert(rwer->buffer_end(), write_block{header, len, 0});
    });
    req->attach(std::bind(&Cgi::Send, this, id, _1, _2),
                [this]{ return 1024*1024 - rwer->wlength();});
}

void Cgi::dump_stat(Dumper dp, void* param){
    dp(param, "Cgi %p %s:\n", this, filename);
    for(auto i: statusmap){
        dp(param, "%" PRIu32": %s\n", i.first, i.second.req->header->geturl().c_str());
    }
}

void getcgi(HttpReq* req, const char* filename, Requester* src){
    if(cgimap.count(filename)) {
        return cgimap[filename]->request(req, src);
    } else {
        int fds[2] = {0, 0};
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {  // 创建管道
            LOGE("[CGI] %s socketpair failed: %s\n", filename, strerror(errno));
            goto err;
        }
        return (new Cgi(filename, fds))->request(req, src);
err:
        if(fds[0]){
            close(fds[0]);
            close(fds[1]);
        }
        req->response(new HttpRes(new HttpResHeader(H500), "[[create socket error]]"));
    }
}


void flushcgi() {
    for(const auto& i:cgimap) {
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

int cgi_response(int fd, const HttpResHeader &res) {
    CGI_Header *header = res.getcgi();
    int ret = write(fd, header, sizeof(CGI_Header) + ntohs(header->contentLength));
    p_free(header);
    return ret;
}

std::map<string, string> getparamsmap(const char* param) {
    return getparamsmap(param, strlen(param));
}


std::map<string, string> getparamsmap(const char *param, size_t len) {
    std::map<string, string> params;
    if(len == 0) {
        return params;
    }
    char paramsbuff[URLLIMIT];
    URLDecode(paramsbuff, param, len);
    char *p=paramsbuff;
    if(*p) {
        for (; ; p = nullptr) {
            char *q = strtok(p, "&");
            if (q == nullptr)
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


int cgi_send(int fd, uint32_t id, const void *buff, size_t len) {
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

int cgi_senderror(int fd, uint32_t id, uint8_t flag){
    char buff[sizeof(CGI_Header)];
    cgi_error((CGI_Header*)buff, id, flag);
    return write(fd, buff, sizeof(buff)) == (int)sizeof(buff) ? 0 : -1;
}
