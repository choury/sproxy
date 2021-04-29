//
// Created by 周威 on 2021/4/21.
//

#ifndef SPROXY_EP_H
#define SPROXY_EP_H

#include <stdint.h>
#include <sys/types.h>

int event_loop(uint32_t timeout_ms);
enum class RW_EVENT{
    NONE = 0,
    READ = 1,
    WRITE = 2,
    READWRITE = READ | WRITE,
    READEOF = 4,
    ERROR = 8,
};

RW_EVENT operator&(RW_EVENT a, RW_EVENT b);
RW_EVENT operator|(RW_EVENT a, RW_EVENT b);
RW_EVENT operator~(RW_EVENT a);
bool operator!(RW_EVENT a);
extern const char *events_string[];

class Ep{
    int fd;
protected:
    RW_EVENT events = RW_EVENT::NONE;
    void setFd(int fd);
    int getFd();
public:
    explicit Ep(int fd);
    virtual ~Ep();
    void setEvents(RW_EVENT events);
    void addEvents(RW_EVENT events);
    void delEvents(RW_EVENT events);
    RW_EVENT getEvents();
    int checkSocket(const char* msg);
    void (Ep::*handleEvent)(RW_EVENT events) = nullptr;
    friend int event_loop(uint32_t timeout_ms);
};

#endif //SPROXY_EP_H
