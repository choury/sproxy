#ifndef CGI_H__
#define CGI_H__

#include "responser.h"
#include "prot/http_pack.h"


// 可用于CGI_Header的type组件的值
#define CGI_REQUEST       1
#define CGI_RESPONSE      2
#define CGI_DATA          3
#define CGI_VALUE         4
#define CGI_RESET         5

#define CGI_LEN_MAX       (BUF_LEN - sizeof(CGI_Header))

struct CGI_Header{
    uint8_t type;
#define CGI_FLAG_UNKONWNNAME     0x20
#define CGI_FLAG_ERROR           0x40
#define CGI_FLAG_END             0x80
    uint8_t flag;
    uint16_t contentLength; //最大65536 - 8 (实际是BUF_LEN - 8)
    uint32_t requestId;
}__attribute__((packed));

struct CGI_NVLenPair{
    uint16_t nameLength;
    uint16_t valueLength;
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
    void readHE(size_t len);
    bool HandleRes(const CGI_Header* header, CgiStatus& status);
    bool HandleValue(const CGI_Header* header, CgiStatus& status);
    bool HandleData(const CGI_Header* header, CgiStatus& Status);
    bool HandleReset(const CGI_Header* header, CgiStatus status);
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
int cgi_response(int fd, const HttpResHeader &req, uint32_t cgi_id);
int cgi_write(int fd, uint32_t id, const void *buff, size_t len);
int cgi_query(int fd, uint32_t id, int name);
int cgi_setvalue(int fd, uint32_t id, int name, const void* value, size_t len);
int cgi_reset(int fd, uint32_t id);
#ifdef  __cplusplus
}
#endif
#endif
