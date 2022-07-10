#include "cgi.h"
#include "req/requester.h"
#include "prot/netio.h"
#include "misc/net.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/config.h"


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


struct CGI_NVLenPair{
    uint16_t nameLength;
    uint16_t valueLength;
}__attribute__((packed));

static char *cgi_addnv(char *p, const string &name, const string &value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *) p;
    cgi_pairs->nameLength = htons(name.size());
    cgi_pairs->valueLength = htons(value.size());
    p = (char *)(cgi_pairs +1);
    memcpy(p, name.c_str(), name.size());
    p += name.size();
    memcpy(p, value.c_str(), value.size());
    return p + value.size();
}

static const char *cgi_getnv(const char* p, string& name, string& value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *)p;
    uint32_t name_len = ntohs(cgi_pairs->nameLength);
    uint32_t value_len = ntohs(cgi_pairs->valueLength);
    p = (const char *)(cgi_pairs + 1);
    name = string(p, name_len);
    p += name_len;
    value = string(p, value_len);
    return p + value_len;
}

static std::multimap<std::string, std::string> decode(const unsigned char *s, size_t len) {
    std::multimap<std::string, std::string> headers;
    const char* p = (const char*)s;
    while(uint32_t(p - (const char*)s) < len){
        string name, value;
        p = cgi_getnv((const char*)p, name, value);
        headers.insert(std::make_pair(name, value));
    }
    return headers;
}

std::shared_ptr<HttpReqHeader> UnpackCgiReq(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(!headers.count(":method")){
        LOGE("wrong frame http request, no method\n");
        return nullptr;
    }
    return std::make_shared<HttpReqHeader>(std::move(headers));
}

std::shared_ptr<HttpResHeader> UnpackCgiRes(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(!headers.count(":status")){
        LOGE("wrong frame http response, no status\n");
        return nullptr;
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

size_t PackCgiReq(std::shared_ptr<const HttpReqHeader> req, void *data, size_t len) {
    char* p = (char*)data;
    for(const auto& i : req->Normalize()){
        p = cgi_addnv(p, i.first, i.second);
    }
    assert(p - (char*)data <= (int)len);
    (void)len;
    return p - (char*)data;
}

size_t PackCgiRes(std::shared_ptr<const HttpResHeader> res, void *data, size_t len) {
    char *p = (char *)data;
    for(const auto& i : res->Normalize()){
        p = cgi_addnv(p, i.first, i.second);
    }
    assert(p - (char*)data <= (int)len);
    (void)len;
    return p - (char*)data;
}

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
        LOGD(DFILE, "<cgi> max fd: %d\n", (int)limits.rlim_cur);
        for(int i = 3; i< (int)limits.rlim_cur; i++){
            if(i == sv[1]){
                continue;
            }
            close(i);
        }
        setenv("ADMIN_SOCK", opt.admin, 1);
        signal(SIGPIPE, SIG_DFL);
        signal(SIGUSR1, SIG_IGN);
        change_process_name(basename(filename));
        LOGD(DFILE, "<cgi> [%s] jump to cgi main\n", basename(filename));
        exit(func(sv[1], basename(filename)));
    }
    // 父进程
    close(sv[1]);   // 关闭管道的子进程端
    /* 现在可在fd[0]中读写数据 */
    rwer = std::make_shared<StreamRWer>(sv[0], nullptr, [this](int ret, int code){
        LOGE("[CGI] %s error: %d/%d\n", basename(filename), ret, code);
        deleteLater(ret);
    });
    rwer->SetReadCB(std::bind(&Cgi::readHE, this, _1, _2, _3));
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
    status.req->detach();
    if(status.res == nullptr){
        status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[cgi failed]]\n"));
    }else {
        status.res->send(ChannelMessage::CHANNEL_ABORT);
    }
    statusmap.erase(id);
}

Cgi::~Cgi() {
    auto statusmapCopy = statusmap;
    for(auto i: statusmapCopy) {
        Clean(i.first, i.second);
    }
    statusmap.clear();
}

void Cgi::Recv(Buffer&& bb) {
    LOGD(DFILE, "<cgi> [%s] stream %" PRIu32 " recv: %zd\n", basename(filename), (int)bb.id, bb.len);
    assert(statusmap.count(bb.id));
    size_t size = bb.len > CGI_LEN_MAX ? CGI_LEN_MAX : bb.len;
    CGI_Header *header = (CGI_Header *) bb.reserve(-(char) sizeof(CGI_Header));
    header->type = CGI_DATA;
    header->flag = size ? 0: CGI_FLAG_END;
    header->requestId = htonl(bb.id);
    header->contentLength = htons(size);
    rwer->buffer_insert(rwer->buffer_end(), std::move(bb));
}


size_t Cgi::readHE(uint64_t, const void* data, size_t len) {
    if(len == 0){
        LOGE("[CGI] %s closed pipe\n", basename(filename));
        deleteLater(PROTOCOL_ERR);
        return 0;
    }
    while(len >= sizeof(CGI_Header)) {
        const CGI_Header *header = (const CGI_Header *)data;
        size_t size = ntohs(header->contentLength) + sizeof(CGI_Header);
        if(len  < size){
            return len;
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
        if(!consumed){
            return len;
        }
        len -= size;
        data = (const char *)data + size;
    }
    return len;
}

bool Cgi::HandleRes(const CGI_Header *cheader, CgiStatus& status){
    uint32_t len = ntohs(cheader->contentLength);
    std::shared_ptr<HttpResHeader> header = UnpackCgiRes(cheader + 1, len);
    header->request_id = ntohl(cheader->requestId);

    LOGD(DFILE, "<cgi> [%s] res %" PRIu32 ": %s\n", basename(filename), header->request_id, header->status);
    if (!header->no_body() && header->get("content-length") == nullptr) {
        header->set("transfer-encoding", "chunked");
    }
    status.res = std::make_shared<HttpRes>(header, [this]{ rwer->Unblock(0);});
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
    if(size > 0) {
        status.res->send((header + 1), size);
    }
    if (header->flag & CGI_FLAG_END) {
        uint32_t id = ntohl(header->requestId);
        status.res->send(nullptr);
        Clean(id, status);
    }
    return true;
}

bool Cgi::HandleError(const CGI_Header* header, CgiStatus& status){
    uint32_t id = ntohl(header->requestId);
    LOG("[CGI] %s %" PRIu32 " error with %d\n", basename(filename), id, header->flag);
    if(header->flag & CGI_FLAG_ABORT){
        Clean(id, status);
    }
    return true;
}

void Cgi::deleteLater(uint32_t errcode){
    evictMe();
    return Server::deleteLater(errcode);
}

void Cgi::Handle(uint32_t id, ChannelMessage::Signal) {
    if(statusmap.count(id) == 0) {
        LOGE("[CGI] %s stream %" PRIu32 " finished, not found\n", basename(filename), id);
        return;
    }
    LOGD(DFILE, "<cgi> [%s] stream %" PRIu32" finished\n", basename(filename), id);
    statusmap.erase(id);
    auto buff = std::make_shared<Block>(sizeof(CGI_Header));
    CGI_Header *header = (CGI_Header *)buff->data();
    cgi_error(header, id, CGI_FLAG_ABORT);
    rwer->buffer_insert(rwer->buffer_end(), Buffer{buff, sizeof(CGI_Header)});
}



void Cgi::request(std::shared_ptr<HttpReq> req, Requester* src) {
    uint32_t id = req->header->request_id;
    LOGD(DFILE, "<cgi> [%s] new request: %" PRIu32 "\n", basename(filename), id);
    statusmap[id] = CgiStatus{
        req,
        nullptr,
    };
    req->header->set("X-Real-IP", src->getid());
    req->header->set("X-Authorized", checkauth(src->getid(), req->header->get("Authorization")));

    auto buff = std::make_shared<Block>(BUF_LEN);
    CGI_Header* const header = (CGI_Header *)buff->data();
    header->type = CGI_REQUEST;
    header->flag = 0;
    header->requestId = htonl(req->header->request_id);
    header->contentLength = htons(PackCgiReq(req->header, header + 1, BUF_LEN - sizeof(CGI_Header)));
    rwer->buffer_insert(rwer->buffer_end(), Buffer{buff, sizeof(CGI_Header) + ntohs(header->contentLength)});
    req->attach([this, id](ChannelMessage& msg){
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DFILE, "<CGI> ignore header for req\n");
            return 1;
        case ChannelMessage::CHANNEL_MSG_DATA:
            msg.data.id = id;
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(id, msg.signal);
            return 0;
        }
        return 0;
    }, [this]{ return rwer->cap(0);});
}

void Cgi::dump_stat(Dumper dp, void* param){
    dp(param, "Cgi %p %s:\n", this, filename);
    for(const auto& i: statusmap){
        dp(param, "  [%" PRIu32"]: %s\n",
           i.first, i.second.req->header->geturl().c_str());
    }
}

void getcgi(std::shared_ptr<HttpReq> req, const char* filename, Requester* src){
    if(cgimap.count(filename)) {
        return cgimap[filename]->request(req, src);
    }
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
    req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[create socket error]]"));
}


void flushcgi() {
    for(const auto& i:cgimap) {
        i.second->deleteLater(PEER_LOST_ERR);
    }
}

int cgi_response(int fd, std::shared_ptr<const HttpResHeader> res) {
    CGI_Header* const header = (CGI_Header *)malloc(BUF_LEN);
    header->type = CGI_RESPONSE;
    header->flag = 0;
    header->requestId = htonl(res->request_id);
    header->contentLength = htons(PackCgiRes(res, header + 1, BUF_LEN - sizeof(CGI_Header)));
    int ret = write(fd, header, sizeof(CGI_Header) + ntohs(header->contentLength));
    free(header);
    return ret;
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
