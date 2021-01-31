#ifndef CGI_H__
#define CGI_H__

#include "responser.h"
#include "prot/http_pack.h"
#include "misc/net.h"

#include <assert.h>
#include <unistd.h>


// 可用于CGI_Header的type组件的值
#define CGI_REQUEST       1
#define CGI_RESPONSE      2
#define CGI_DATA          3
#define CGI_VALUE         4
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

struct CGI_NVLenPair{
    uint16_t nameLength;
    uint16_t valueLength;
}__attribute__((packed));

#define CGI_ERROR_NOAUTH           1
#define CGI_ERROR_UNKONWNNAME      2
#define CGI_ERROR_INTERNAL         3
struct CGI_Error{
    uint32_t error;
}__attribute__((packed));


#define CGI_NAME_BUFFLEFT     1
#define CGI_NAME_STRATEGYGET  2
#define CGI_NAME_STRATEGYADD  3
#define CGI_NAME_STRATEGYDEL  4
#define CGI_NAME_GETPROXY     5
#define CGI_NAME_SETPROXY     6
#define CGI_NAME_LOGIN        7

struct CGI_NameValue{
    uint32_t name;
    uint8_t value[0];
}__attribute__((packed));

struct CgiStatus{
    HttpReq* req;
    HttpRes* res;
    char sourceip[INET6_ADDRSTRLEN];
};

class Cgi:public Responser{
    char filename[URLLIMIT];
    std::map<uint32_t, CgiStatus> statusmap;
    void evictMe();
    void Clean(uint32_t id, CgiStatus& status);
    void readHE(size_t len);
    bool HandleRes(const CGI_Header* header, CgiStatus& status);
    bool HandleValue(const CGI_Header* header, CgiStatus& status);
    bool HandleData(const CGI_Header* header, CgiStatus& Status);
    bool HandleError(const CGI_Header* header, CgiStatus& status);
    void Send(uint32_t id, void *buff, size_t size);
public:
    explicit Cgi(const char* filename, int sv[2]);
    virtual ~Cgi() override;

    virtual void deleteLater(uint32_t errcode) override;
    virtual void request(HttpReq* req, Requester*)override;
    virtual void dump_stat(Dumper dp, void* param) override;
};

void getcgi(HttpReq* req, const char *filename, Requester *src);

class Cookie{
public:
    const char *name = nullptr;
    const char *value = nullptr;
    const char *path= nullptr;
    const char *domain = nullptr;
    uint32_t maxage = 0;
    Cookie() = default;
    Cookie(const char *name, const char *value):name(name), value(value){}
    void set(const char* name, const char *value){
        this->name = name;
        this->value = value;
    }
};

void flushcgi();

std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param, size_t len);
std::map<std::string, std::string> __attribute__((weak)) getparamsmap(const char *param);
void addcookie(HttpResHeader &res, const Cookie &cookie);
#ifdef  __cplusplus
extern "C" {
#endif
typedef int (cgifunc)(int fd);
cgifunc cgimain;
int cgi_response(int fd, const HttpResHeader &req);
int cgi_send(int fd, uint32_t id, const void *buff, size_t len);
int cgi_query(int fd, uint32_t id, int name);
int cgi_setvalue(int fd, uint32_t id, int name, const void* value, size_t len);
int cgi_senderror(int fd, uint32_t id, uint32_t error, uint8_t flag);
#ifdef  __cplusplus
}
#endif


class CgiHandler{
protected:
    const int fd;
    uint32_t flag = 0;
    HttpReqHeader* req = nullptr;
    std::map<std::string, std::string> params;
    void NotImplemented(){
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        HttpResHeader res(H405, sizeof(H405));
        Response(res);
        Finish();
    }
    void BadRequest(){
        if((flag & HTTP_REQ_COMPLETED) == 0) {
            return;
        }
        HttpResHeader res(H400, sizeof(H400));
        Response(res);
        Finish();
    }
    virtual void ERROR(const CGI_Header* header){
        if(header->flag & CGI_FLAG_ABORT){
            flag |= HTTP_REQ_EOF;
            return;
        }
        CGI_Error* cgi_error = (CGI_Error*)(header+1);
        switch(ntohl(cgi_error->error)){
        case CGI_ERROR_NOAUTH:{
            HttpResHeader res(H403, sizeof(H403));
            Response(res);
            break;
        }
        case CGI_ERROR_UNKONWNNAME:{
            HttpResHeader res(H404, sizeof(H404));
            Response(res);
            break;
        }
        default:{
            HttpResHeader res(H500, sizeof(H500));
            Response(res);
            break;
        }
        }
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
    virtual void Finish(){
        if((flag & HTTP_RES_EOF) || (flag & HTTP_REQ_EOF)){
            return;
        }
        if((flag & HTTP_RES_COMPLETED) == 0){
            cgi_senderror(fd, req->request_id, CGI_ERROR_INTERNAL, CGI_FLAG_ABORT);
        }else{
            cgi_send(fd, req->request_id, "", 0);
        }
        flag |= HTTP_RES_EOF;
    }
    void Response(HttpResHeader& res){
        if(flag & HTTP_RES_COMPLETED){
            return;
        }
        flag |= HTTP_RES_COMPLETED;
        res.request_id = req->request_id;
        cgi_response(fd, res);
    }
    void Send(const char* buf, size_t len){
        cgi_send(fd, req->request_id, buf, len);
    }
    void Query(int name) {
        cgi_query(fd, req->request_id, name);
    }
    void SetValue(int name, const char* value, size_t len){
        cgi_setvalue(fd, req->request_id, name, value, len);
    }
    void SendError(uint32_t error){
        flag |= HTTP_RES_EOF;
        if(flag & HTTP_REQ_EOF) {
            return;
        }
        cgi_senderror(fd, req->request_id, error, CGI_FLAG_ABORT);
    }
public:
    CgiHandler(int fd, const CGI_Header* header):fd(fd){
        assert(header->type == CGI_REQUEST);
        req = new HttpReqHeader(header);
        auto param = req->getparamsmap();
        params.insert(param.begin(), param.end());
    }
    virtual ~CgiHandler(){
        Finish();
        delete req;
    }
    void handle(const CGI_Header* header, const char* name){
        if(header->type == CGI_ERROR){
            return ERROR(header);
        }
        if((flag & HTTP_REQ_COMPLETED) &&
            ((header->type == CGI_REQUEST) || (header->type == CGI_DATA)))
        {
            LOGE("[CGI] %s %d get date after completed\n", name, req->request_id);
            SendError(CGI_ERROR_INTERNAL);
            return;
        }
        if((header->flag & CGI_FLAG_END) && (header->type == CGI_DATA)) {
            flag |= HTTP_REQ_COMPLETED;
            LOGD(DFILE, "<cgi> [%s] req completed: %d\n", name, req->request_id);
        }
        if(req->ismethod("get")){
            return GET(header);
        }else if(req->ismethod("post")){
            return POST(header);
        }else if(req->ismethod("delete")){
            return DELETE(header);
        }else if(req->ismethod("put")) {
            return PUT(header);
        }
        NotImplemented();
    }
    bool eof() const{
        return (flag & HTTP_RES_EOF) || (flag & HTTP_REQ_EOF);
    }
};


#define CGIMAIN(__handler) \
static std::map<uint32_t, CgiHandler*> cgimap; \
int cgimain(int fd){       \
    LOGD(DFILE, "<cgi> [%s] cgimain start\n", __FILE__); \
    ssize_t readlen; \
    char buff[CGI_LEN_MAX]; \
    while((readlen = read(fd, buff, sizeof(CGI_Header))) > 0){ \
        CGI_Header *header = (CGI_Header *)buff; \
        int __attribute__((unused)) ret = read(fd, buff + readlen, ntohs(header->contentLength)); \
        assert(ret == ntohs(header->contentLength)); \
        uint32_t id = ntohl(header->requestId); \
        LOGD(DFILE, "<cgi> [%s] get id: %d, type: %d\n", __FILE__, id, header->type); \
        if(header->type == CGI_REQUEST){ \
            assert(cgimap.count(id) == 0);  \
            LOGD(DFILE, "<cgi> [%s] new request: %d\n", __FILE__, id);   \
            cgimap.emplace(id, new __handler(fd, header)); \
        } \
        if(cgimap.count(id) == 0){             \
            LOGD(DFILE, "<cgi> [%s] unknown id: %d\n", __FILE__, id);   \
            if(header->type != CGI_ERROR){     \
                cgi_senderror(fd, id, CGI_ERROR_INTERNAL, CGI_FLAG_ABORT); \
            }         \
            continue; \
        } \
        CgiHandler* h = cgimap[id]; \
        h->handle(header, __FILE__); \
        if(h->eof()){ \
            cgimap.erase(id); \
            delete h; \
        } \
    } \
    for(auto i: cgimap){ \
        delete i.second; \
    } \
    cgimap.clear(); \
    LOGD(DFILE, "<cgi> [%s] cgimain exit\n", __FILE__); \
    return 0; \
} 

#endif
