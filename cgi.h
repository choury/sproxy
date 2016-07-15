#ifndef CGI_H__
#define CGI_H__

#include "responser.h"
#include "parse.h"
#include "binmap.h"

#include <list>

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
    uint32_t value;
}__attribute__((packed));

class Guest;

class Cgi:public Responser{
    char filename[URLLIMIT];
    char cgi_buff[CGI_LEN_MAX];
    size_t cgi_getlen  = 0;
    size_t cgi_outlen  = 0;
    uint32_t curid = 1;
    binmap<std::pair<Guest *, uint32_t>, uint32_t> idmap;
    std::set<Peer *> waitlist;
    virtual void defaultHE(uint32_t events);
    enum {WaitHeadr,
          WaitBody,
          HandleRes,
          HandleValue,
          HandleData,
          HandleLeft
    }status = WaitHeadr;
    void InProc();
public:
    Cgi(HttpReqHeader& req);
    virtual ~Cgi();
    virtual ssize_t Write(void *buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual ssize_t Write(const void *buff, size_t size, Peer* who, uint32_t id=0)override;
    virtual void wait(Peer *who)override;
    virtual void clean(uint32_t errcode, Peer* who, uint32_t id = 0)override;
    virtual int showerrinfo(int ret,const char *s)override;
    virtual Ptr request(HttpReqHeader &req)override;
    static Ptr getcgi(HttpReqHeader &req);
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
int cgi_response(int fd, const HttpResHeader &req);
int cgi_write(int fd, uint32_t id, const void *buff, size_t len);
#ifdef  __cplusplus
}
#endif
#endif
