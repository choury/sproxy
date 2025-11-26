#ifndef CGI_H__
#define CGI_H__

#include "responser.h"

#include <unistd.h>

#include <atomic>


// 可用于CGI_Header的type组件的值
#define CGI_REQUEST       1
#define CGI_RESPONSE      2
#define CGI_DATA          3
#define CGI_ERROR         5

#define CGI_LEN_MAX       (BUF_LEN - sizeof(CGI_Header))

struct CGI_Header{
    uint8_t type;
#define CGI_FLAG_ABORT           0x40   //only used for error packet
#define CGI_FLAG_END             0x80   //only used for data and value packet
    uint8_t flag;
    uint16_t contentLength; //最大65536 - 8 (实际是BUF_LEN - 8)
    uint32_t requestId;
    char     data[0];
}__attribute__((packed));


size_t PackCgiReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
size_t PackCgiRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);

std::shared_ptr<HttpReqHeader> UnpackCgiReq(const void* header, size_t len);
std::shared_ptr<HttpResHeader> UnpackCgiRes(const void* header, size_t len);


class Cgi:public Responser{
    struct CgiStatus{
        std::shared_ptr<HttpReqHeader> req;
        std::shared_ptr<MemRWer>       rw;
        std::shared_ptr<IRWerCallback> cb;
    };

    char filename[URLLIMIT];
    pid_t pid;
    std::map<uint32_t, CgiStatus> statusmap;
    void evictMe();
    void Clean(uint32_t id, CgiStatus& status);
    size_t readHE(Buffer&& bb);
    bool HandleRes(const CGI_Header* header, CgiStatus& status);
    bool HandleData(const CGI_Header* header, CgiStatus& Status);
    bool HandleError(const CGI_Header* header, CgiStatus& status);
public:
    explicit Cgi(const char* filename, int svs[2], int cvs[2]);
    virtual ~Cgi() override;

    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw)override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

void getcgi(std::shared_ptr<HttpReqHeader> req, const char *filename, std::shared_ptr<MemRWer> rw);


void flushcgi();

class SpinLock {
    std::atomic_flag f_ = ATOMIC_FLAG_INIT;
public:
    SpinLock() = default;
    SpinLock(const SpinLock&) = delete;
    SpinLock& operator=(const SpinLock&) = delete;
    void lock() { while(f_.test_and_set(std::memory_order_acquire)); }
    void unlock() { f_.clear(std::memory_order_release); }
};

#ifdef  __cplusplus
extern "C" {
#endif
typedef int (cgifunc)(int sfd, int cfd, const char* name);
cgifunc cgimain;
int cgi_response(int fd, SpinLock& l, std::shared_ptr<const HttpResHeader> res);
int cgi_send(int fd, SpinLock& l, uint32_t id, const void *buff, size_t len);
int cgi_senderror(int fd, uint32_t id, uint8_t flag);
#ifdef  __cplusplus
}
#endif


class CgiHandler {
protected:
    const int sfd;
    const int cfd;
    const char name[FILENAME_MAX];
    uint32_t id = 0;  //request id
    std::atomic<uint32_t> flag = 0;
    std::shared_ptr<const HttpReqHeader> req;
    std::map<std::string, std::string> params;  //should be read only
    void NotImplemented(){
        if((flag.load(std::memory_order_acquire)  & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        Response(HttpResHeader::create(S405, sizeof(S405), req->request_id));
        Finish();
    }
    void BadRequest(){
        if((flag.load(std::memory_order_acquire)  & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        Response(HttpResHeader::create(S400, sizeof(S400), req->request_id));
        Finish();
    }
    virtual void ERROR(const CGI_Header* header){
        if(header->flag & CGI_FLAG_ABORT){
            flag.fetch_or(HTTP_CLOSED_F, std::memory_order_release);
            return;
        }
        Response(HttpResHeader::create(S500, sizeof(S500), req->request_id));
        Finish();
    }
    virtual void GET(const CGI_Header*){
        NotImplemented();
    }
    virtual void PUT(const CGI_Header*){
        NotImplemented();
    }
    virtual void POST(const CGI_Header*){
        NotImplemented();
    }
    virtual void DELETE(const CGI_Header*){
        NotImplemented();
    }
    virtual void CustomMethod(const std::string& /*method*/, const CGI_Header*) {
        NotImplemented();
    }
    void Finish(){
        if(flag.load(std::memory_order_acquire)  & HTTP_CLOSED_F){
            return;
        }
        LOGD(DFILE, "<cgi> [%s] res finished: %d\n", name, id);
        if((flag.load(std::memory_order_acquire)  & HTTP_RES_COMPLETED) == 0){
            cgi_senderror(sfd, id, CGI_FLAG_ABORT);
        }else{
            cgi_send(sfd, l, id, "", 0);
        }
        flag.fetch_or(HTTP_CLOSED_F, std::memory_order_release);
    }
    void Response(std::shared_ptr<HttpResHeader> res){
        if(flag.load(std::memory_order_acquire)  & HTTP_RES_COMPLETED){
            return;
        }
        flag.fetch_or(HTTP_RES_COMPLETED, std::memory_order_release);
        res->request_id = id;
        cgi_response(sfd, l, res);
    }

    void Send(const char* buf, size_t len) const{
        cgi_send(sfd, l, id, buf, len);
    }
    void Abort(){
        if(flag.load(std::memory_order_acquire)  & HTTP_CLOSED_F) {
            return;
        }
        flag.fetch_or(HTTP_CLOSED_F, std::memory_order_release);
        cgi_senderror(sfd, id, CGI_FLAG_ABORT);
    }
public:
    static SpinLock l;  //保护 fd
    static std::map<uint32_t, std::shared_ptr<CgiHandler>> cgimap;
    CgiHandler(int sfd, int cfd, const char* name, const CGI_Header* header): sfd(sfd), cfd(cfd), name{} {
        strcpy(const_cast<char*>(this->name), name);
        assert(header->type == CGI_REQUEST);
        uint32_t len = ntohs(header->contentLength);
        req = UnpackCgiReq(header->data, len);
        id = ntohl(header->requestId);
        params = req->getparamsmap();
    }
    virtual ~CgiHandler(){
        LOGD(DFILE, "<cgi> [%s] handler exit: %d\n", name, id);
        Finish();
    }
    void handle(const CGI_Header* header){
        if(flag.load(std::memory_order_acquire)  & HTTP_CLOSED_F){
            return;
        }
        if(header->type == CGI_ERROR){
            return ERROR(header);
        }
        if((flag.load(std::memory_order_acquire)  & HTTP_REQ_COMPLETED) &&
            ((header->type == CGI_REQUEST) || (header->type == CGI_DATA)))
        {
            LOGE("[CGI] %s %d get date after completed\n", name, id);
            Abort();
            return;
        }
        if((header->flag & CGI_FLAG_END) && (header->type == CGI_DATA)) {
            flag.fetch_or(HTTP_REQ_COMPLETED, std::memory_order_release);
            LOGD(DFILE, "<cgi> [%s] req completed: %d\n", name, id);
        }
        if(req->no_body() && (flag.load(std::memory_order_acquire)  & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        if(req->ismethod("GET") || req->ismethod("HEAD")){
            return GET(header);
        }else if(req->ismethod("POST")){
            return POST(header);
        }else if(req->ismethod("DELETE")){
            return DELETE(header);
        }else if(req->ismethod("PUT")) {
            return PUT(header);
        }else {
            return CustomMethod(req->method, header);
        }
    }
    [[nodiscard]] bool eof() const{
        return flag.load(std::memory_order_acquire) & HTTP_CLOSED_F;
    }
};


#define CGIMAIN(__handler) \
SpinLock CgiHandler::l; \
std::map<uint32_t, std::shared_ptr<CgiHandler>> CgiHandler::cgimap; \
int cgimain(int sfd, int cfd, const char* name){       \
    LOGD(DFILE, "<cgi> [%s] cgimain start\n", name); \
    ssize_t readlen; \
    char buff[BUF_LEN]; \
    while((readlen = read(sfd, buff, sizeof(CGI_Header))) > 0){ \
        CGI_Header *header = (CGI_Header *)buff; \
        size_t content_len = ntohs(header->contentLength); \
        if(content_len > sizeof(buff) - sizeof(CGI_Header)) { \
            LOGE("[CGI] %s content too large: %zu\n", name, content_len); \
            cgi_senderror(sfd, ntohl(header->requestId), CGI_FLAG_ABORT); \
            continue; \
        } \
        int __attribute__((unused)) ret = read(sfd, buff + readlen, content_len); \
        assert(ret == ntohs(header->contentLength)); \
        uint32_t id = ntohl(header->requestId); \
        LOGD(DFILE, "<cgi> [%s] get id: %d, type: %d\n", name, id, header->type); \
        if(header->type == CGI_REQUEST){ \
            assert(CgiHandler::cgimap.count(id) == 0);  \
            LOGD(DFILE, "<cgi> [%s] new request: %d\n", name, id);   \
            CgiHandler::cgimap.emplace(id, std::make_shared<__handler>(sfd, cfd, name, header)); \
        }                  \
        for(auto it = CgiHandler::cgimap.begin(); it != CgiHandler::cgimap.end();) {   \
            if(it->second->eof()) {                 \
                it = CgiHandler::cgimap.erase(it);  \
            } else {                                \
                it++;                               \
            }                                       \
        }                                           \
        if(CgiHandler::cgimap.count(id) == 0){      \
            LOGD(DFILE, "<cgi> [%s] unknown id: %d\n", name, id);   \
            if(header->type != CGI_ERROR){     \
                cgi_senderror(sfd, id, CGI_FLAG_ABORT); \
            }         \
            continue; \
        } \
        auto h = CgiHandler::cgimap[id]; \
        h->handle(header); \
    } \
    CgiHandler::cgimap.clear(); \
    LOGD(DFILE, "<cgi> [%s] cgimain exit\n", name); \
    return 0; \
}

#endif
