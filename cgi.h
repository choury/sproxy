#ifndef CGI_H__
#define CGI_H__

#include "responser.h"
#include "parse.h"


// 可用于CGI_Header的type组件的值
#define CGI_REQUEST       1
#define CGI_RESPONSE      2
#define CGI_DATA          3
#define CGI_VALUE         4

#define CGI_LEN_MAX       (BUF_LEN - sizeof(CGI_Header))

struct CGI_Header{
    uint8_t type;
#define CGI_FLAG_ACK      1
#define CGI_FLAG_END      2
    uint8_t flag;
    uint16_t contentLength; //最大65536 - 8 (实际是BUF_LEN - 8)
    uint32_t requestId;
}__attribute__((packed));

struct CGI_NVLenPair{
    uint16_t nameLength;
    uint16_t valueLength;
}__attribute__((packed));


#define CGI_NAME_BUFFLEFT  1
struct CGI_NameValue{
    uint32_t name;
    uint8_t value[0];
}__attribute__((packed));

class Requester;

struct CgiStatus{
    Requester *req_ptr;
    uint32_t   req_id;
};

class Cgi:public Responser{
    char filename[URLLIMIT];
    char cgi_buff[BUF_LEN];
    size_t cgi_getlen  = 0;
    size_t cgi_outlen  = 0;
    uint32_t curid = 1;
    std::map<uint32_t, CgiStatus> statusmap;
    std::set<uint32_t> waitlist;
    virtual void defaultHE(uint32_t events);
    enum class Status{
        WaitHeadr, WaitBody, HandleRes, HandleValue, HandleData, HandleLeft
    }status = Status::WaitHeadr;
    void InProc();
public:
    explicit Cgi(HttpReqHeader& req);
    virtual ~Cgi();
    virtual ssize_t Write(void *buff, size_t size, uint32_t id)override;
    virtual void wait(uint32_t id)override;
    virtual void clean(uint32_t errcode, uint32_t id)override;
    virtual uint32_t request(HttpReqHeader&& req)override;
    static Cgi* getcgi(HttpReqHeader& req);
};

class Cookie{
public:
    const char *name;
    const char *value;
    const char *path= nullptr;
    const char *domain = nullptr;
    uint32_t maxage = 0;
    Cookie(const char *name, const char *value):name(name), value(value){}
    void set(const char* name, const char *value){
        this->name = name;
        this->value = value;
    }
};

void flushcgi();

std::map<std::string, std::string> getparamsmap(const char *param, size_t len);
std::map<std::string, std::string> getparamsmap(const char *param);
void addcookie(HttpResHeader &res, const Cookie &cookie);
#ifdef  __cplusplus
extern "C" {
#endif
typedef int (cgifunc)(int fd);
cgifunc cgimain;
int cgi_response(int fd, const HttpResHeader &req, uint32_t cgi_id);
int cgi_write(int fd, uint32_t id, const void *buff, size_t len);
#ifdef  __cplusplus
}
#endif
#endif
