#ifndef __CGI_H__
#define __CGI_H__

#include "peer.h"
#include "guest.h"
#include "parse.h"

class Cgi:public Peer{
    HttpReqHeader req;
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    virtual ssize_t DataProc(const void *buff,size_t size)override;
public:
    Cgi(HttpReqHeader &req,Guest* guest);
    static Cgi *getcgi(HttpReqHeader &req,Guest *guest);
    virtual int showerrinfo(int ret,const char *s)override;
};

#endif