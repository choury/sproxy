#ifndef CGI_H__
#define CGI_H__

#include "responser.h"
#include "prot/http/http_def.h"
#include "misc/net.h"

#include <assert.h>
#include <unistd.h>


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
}__attribute__((packed));


size_t PackCgiReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
size_t PackCgiRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);

std::shared_ptr<HttpReqHeader> UnpackCgiReq(const void* header, size_t len);
std::shared_ptr<HttpResHeader> UnpackCgiRes(const void* header, size_t len);


class Cgi:public Responser{
    struct CgiStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
    };

    char filename[URLLIMIT];
    pid_t pid;
    std::map<uint32_t, CgiStatus> statusmap;
    void evictMe();
    void Clean(uint32_t id, CgiStatus& status);
    size_t readHE(const Buffer& bb);
    bool HandleRes(const CGI_Header* header, CgiStatus& status);
    bool HandleData(const CGI_Header* header, CgiStatus& Status);
    bool HandleError(const CGI_Header* header, CgiStatus& status);
    void Recv(Buffer&& bb);
    void Handle(uint32_t id, Signal s);
public:
    explicit Cgi(const char* filename, int svs[2], int cvs[2]);
    virtual ~Cgi() override;

    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(std::shared_ptr<HttpReq> req, Requester*)override;
    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

void getcgi(std::shared_ptr<HttpReq> req, const char *filename, Requester *src);


void flushcgi();

#ifdef  __cplusplus
extern "C" {
#endif
typedef int (cgifunc)(int sfd, int cfd, const char* name);
cgifunc cgimain;
int cgi_response(int fd, std::shared_ptr<const HttpResHeader> res);
int cgi_send(int fd, uint32_t id, const void *buff, size_t len);
int cgi_senderror(int fd, uint32_t id, uint8_t flag);
#ifdef  __cplusplus
}
#endif


class CgiHandler{
protected:
    const int sfd;
    const int cfd;
    char name[FILENAME_MAX];
    uint32_t flag = 0;
    std::shared_ptr<HttpReqHeader> req;
    std::map<std::string, std::string> params;
    void NotImplemented(){
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        Response(UnpackHttpRes(H405, sizeof(H405)));
        Finish();
    }
    void BadRequest(){
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        Response(UnpackHttpRes(H400, sizeof(H400)));
        Finish();
    }
    virtual void ERROR(const CGI_Header* header){
        if(header->flag & CGI_FLAG_ABORT){
            flag |= HTTP_CLOSED_F;
            return;
        }
        Response(UnpackHttpRes(H500, sizeof(H500)));
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
    void Finish(){
        if(flag & HTTP_CLOSED_F){
            return;
        }
        LOGD(DFILE, "<cgi> [%s] res finished: %d\n", name, req->request_id);
        if((flag & HTTP_RES_COMPLETED) == 0){
            cgi_senderror(sfd, req->request_id, CGI_FLAG_ABORT);
        }else{
            cgi_send(sfd, req->request_id, "", 0);
        }
        flag |= HTTP_CLOSED_F;
    }
    void Response(std::shared_ptr<HttpResHeader> res){
        if(flag & HTTP_RES_COMPLETED){
            return;
        }
        flag |= HTTP_RES_COMPLETED;
        res->request_id = req->request_id;
        cgi_response(sfd, res);
    }

    void Send(const char* buf, size_t len){
        cgi_send(sfd, req->request_id, buf, len);
    }
    void Abort(){
        if(flag & HTTP_CLOSED_F) {
            return;
        }
        flag |= HTTP_CLOSED_F;
        cgi_senderror(sfd, req->request_id, CGI_FLAG_ABORT);
    }
public:
    CgiHandler(int sfd, int cfd, const char*name, const CGI_Header* header):sfd(sfd), cfd(cfd){
        strcpy(this->name, name);
        assert(header->type == CGI_REQUEST);
        uint32_t len = ntohs(header->contentLength);
        req = UnpackCgiReq(header+1, len);
        req->request_id = ntohl(header->requestId);
        auto param = req->getparamsmap();
        params.insert(param.begin(), param.end());
    }
    virtual ~CgiHandler(){
        Finish();
    }
    void handle(const CGI_Header* header){
        if(header->type == CGI_ERROR){
            return ERROR(header);
        }
        if((flag & HTTP_REQ_COMPLETED) &&
            ((header->type == CGI_REQUEST) || (header->type == CGI_DATA)))
        {
            LOGE("[CGI] %s %d get date after completed\n", name, req->request_id);
            Abort();
            return;
        }
        if((header->flag & CGI_FLAG_END) && (header->type == CGI_DATA)) {
            flag |= HTTP_REQ_COMPLETED;
            LOGD(DFILE, "<cgi> [%s] req completed: %d\n", name, req->request_id);
        }
        if(req->ismethod("GET")){
            return GET(header);
        }else if(req->ismethod("POST")){
            return POST(header);
        }else if(req->ismethod("DELETE")){
            return DELETE(header);
        }else if(req->ismethod("PUT")) {
            return PUT(header);
        }
        NotImplemented();
    }
    [[nodiscard]] bool eof() const{
        return (flag & HTTP_CLOSED_F);
    }
};


#define CGIMAIN(__handler) \
static std::map<uint32_t, CgiHandler*> cgimap; \
int cgimain(int sfd, int cfd, const char* name){       \
    LOGD(DFILE, "<cgi> [%s] cgimain start\n", name); \
    ssize_t readlen; \
    char buff[CGI_LEN_MAX]; \
    while((readlen = read(sfd, buff, sizeof(CGI_Header))) > 0){ \
        CGI_Header *header = (CGI_Header *)buff; \
        int __attribute__((unused)) ret = read(sfd, buff + readlen, ntohs(header->contentLength)); \
        assert(ret == ntohs(header->contentLength)); \
        uint32_t id = ntohl(header->requestId); \
        LOGD(DFILE, "<cgi> [%s] get id: %d, type: %d\n", name, id, header->type); \
        if(header->type == CGI_REQUEST){ \
            assert(cgimap.count(id) == 0);  \
            LOGD(DFILE, "<cgi> [%s] new request: %d\n", name, id);   \
            cgimap.emplace(id, new __handler(sfd, cfd, name, header)); \
        } \
        if(cgimap.count(id) == 0){             \
            LOGD(DFILE, "<cgi> [%s] unknown id: %d\n", name, id);   \
            if(header->type != CGI_ERROR){     \
                cgi_senderror(sfd, id, CGI_FLAG_ABORT); \
            }         \
            continue; \
        } \
        CgiHandler* h = cgimap[id]; \
        h->handle(header); \
        if(h->eof()){ \
            cgimap.erase(id); \
            delete h; \
        } \
    } \
    for(auto i: cgimap){ \
        delete i.second; \
    } \
    cgimap.clear(); \
    LOGD(DFILE, "<cgi> [%s] cgimain exit\n", name); \
    return 0; \
} 

#endif
