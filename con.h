#ifndef __CON_H__
#define __CON_H__

#include <sys/epoll.h>

extern int efd;

class Con {
public:
    void (Con::*handleEvent)(uint32_t events);
    virtual ~Con() {}
};


#endif
