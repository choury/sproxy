#ifndef CGI_H__
#define CGI_H__

#include "peer.h"
#include "guest.h"
#include "parse.h"

// 可用于CGI_Header的type组件的值
#define CGI_REQUEST       1
#define CGI_RESPONSE      2
#define CGI_DATA          3

#define CGI_LEN_MAX       (65536 - sizeof(CGI_Header))

struct CGI_Header{
    uint8_t type;
    uint8_t flag;
    uint16_t contentLength; //最大65536 - 8
    uint32_t requestId;
}__attribute__((packed));

struct CGI_NameValuePair{
    uint16_t nameLength;
    uint16_t valueLength;
}__attribute__((packed));


class Cgi:public Peer{
    char cgi_buff[CGI_LEN_MAX];
    size_t cgi_getlen  = 0;
    size_t cgi_outlen  = 0;
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events)override;
    enum {WaitHeadr,WaitBody,HandleRes,HandleData, HandleLeft}status = WaitHeadr;
    void InProc();
    void Request(HttpReqHeader &req,Guest *guest);
public:
    Cgi(const char *filename);
    virtual int showerrinfo(int ret,const char *s)override;
    static Cgi *getcgi(HttpReqHeader &req, Guest *guest);
};

#ifdef  __cplusplus
extern "C" {
#endif
int cgi_write(int fd, uint32_t id, const void *buff, size_t len);
#ifdef  __cplusplus
}
#endif
#endif