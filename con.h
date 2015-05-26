#ifndef CON_H__
#define CON_H__

#include <stdint.h>

extern int efd;

class Con {
public:
    void (Con::*handleEvent)(uint32_t events)=nullptr;
    virtual ~Con() {}
};


#endif
