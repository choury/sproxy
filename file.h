#ifndef __FILE_H__
#define __FILE_H__

#include "peer.h"
#include "guest.h"
#include "parse.h"

class File:public Peer{
    int ffd;
    HttpReqHeader req;
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    virtual ssize_t DataProc(const void *buff,size_t size)override;
public:
    File(HttpReqHeader &req,Guest* guest);
    static File *getfile(HttpReqHeader &req,Guest *guest);
    virtual int showerrinfo(int ret,const char *s)override;
};

#endif