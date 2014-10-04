#ifndef __CON_H__
#define __CON_H__

class Con{
public:
    virtual void handleEvent(uint32_t events)=0;
};


#endif