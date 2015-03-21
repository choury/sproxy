#ifndef __FILE_H__
#define __FILE_H__

#include "peer.h"
#include "guest.h"
#include "parse.h"

class File:public Peer{
    int ffd = 0;
protected:
    HttpReqHeader req;
    virtual void defaultHE(uint32_t events);
    void closeHE(uint32_t events)override;
public:
    File(HttpReqHeader &req, Guest* guest);
    static File *getfile(HttpReqHeader &req, Guest *guest);
    int showerrinfo(int ret, const char *s)override;
};

#endif