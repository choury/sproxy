//
// Created by choury on 2021/4/21.
//

#include "ep.h"
#include "common/common.h"
#include "misc/net.h"

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#include <sys/signalfd.h>
#endif

extern int efd;

//单轮事件循环最多等待的事件数，epoll_wait/kevent的批量和pending_events数组共用
#define MAX_LOOP_EVENTS 200

//单批事件用扁平数组暂存，替代std::map(原来每个事件一次树节点分配+平衡)
//setFd/close时通过clear_pending把待处理事件置为NONE，防止同批内Ep被销毁后派发到悬垂指针
struct PendingEvent {
    Ep* ep;
    RW_EVENT event;
};
static PendingEvent pending_events[MAX_LOOP_EVENTS];
static size_t pending_count = 0;

static void push_pending(Ep* ep, RW_EVENT event) {
#ifdef __APPLE__
    //kqueue会按filter把同一fd的读写拆成两条事件，需要合并
    for(size_t i = 0; i < pending_count; i++){
        if(pending_events[i].ep == ep){
            pending_events[i].event = pending_events[i].event | event;
            return;
        }
    }
#endif
    assert(pending_count < MAX_LOOP_EVENTS);
    pending_events[pending_count++] = {ep, event};
}

static void clear_pending(Ep* ep) {
    for(size_t i = 0; i < pending_count; i++){
        if(pending_events[i].ep == ep){
            LOGD(DEVENT, "%p remove pending_events\n", ep);
            pending_events[i].event = RW_EVENT::NONE;
        }
    }
}

const char *events_string[]= {
        "nullptr",
        "READ",
        "WRITE",
        "READ|WRITE",
        "READEOF",
        "READEOF|READ",
        "READEOF|WRITE",
        "READEOF|READ|WRITE",
        "ERROR",
        "ERROR|READ",
        "ERROR|WRITE",
        "ERROR|READ|WRITE",
        "ERROR|READEOF",
        "ERROR|READEOF|READ",
        "ERROR|READEOF|WRITE",
        "ERROR|READEOF|READ|WRITE",
};

RW_EVENT operator&(RW_EVENT a, RW_EVENT b){
    return RW_EVENT(int(a) & int(b));
}

RW_EVENT operator|(RW_EVENT a, RW_EVENT b){
    return RW_EVENT(int(a) | int(b));
}

RW_EVENT operator~(RW_EVENT a){
    return RW_EVENT(~static_cast<int>(a));
}

bool operator!(RW_EVENT a){
    return a == RW_EVENT::NONE;
}

#ifdef __linux__
static RW_EVENT convertEpoll(uint32_t events){
    RW_EVENT rwevents = RW_EVENT::NONE;
    if(events & EPOLLERR){
        rwevents = rwevents | RW_EVENT::ERROR;
    }
    if(events & EPOLLIN){
        rwevents = rwevents | RW_EVENT::READ;
    }
    if(events & EPOLLRDHUP || events & EPOLLHUP){
        rwevents = rwevents | RW_EVENT::READEOF;
    }
    if(events & EPOLLOUT){
        rwevents = rwevents | RW_EVENT::WRITE;
    }
    return rwevents;
}
#endif

#ifdef __APPLE__
static RW_EVENT convertKevent(const struct kevent& event){
    RW_EVENT rwevent = RW_EVENT::NONE;
    if(event.flags & EV_ERROR){
        rwevent = rwevent | RW_EVENT::ERROR;
    }
    if (event.flags & EV_EOF){
        rwevent = rwevent | RW_EVENT::READEOF;
    }
    if (event.filter == EVFILT_READ){
        rwevent = rwevent | RW_EVENT::READ;
    }
    if (event.filter == EVFILT_WRITE){
        rwevent = rwevent | RW_EVENT::WRITE;
    }
    return rwevent;
}
#endif


Ep::Ep(int fd):fd(fd){
    LOGD(DEVENT, "%p set fd: %d\n", this, fd);
    SetSocketUnblock(fd);
}

Ep::~Ep(){
    if(fd >= 0){
        setFd(-1);
    } else {
        assert(events == RW_EVENT::NONE);
    }
}

void Ep::setFd(int fd){
    if(this->fd >= 0){
#if __linux__
        epoll_ctl(efd, EPOLL_CTL_DEL, this->fd, nullptr);
#endif
#if __APPLE__
        struct kevent event[2];
        EV_SET(&event[0], this->fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
        EV_SET(&event[1], this->fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
        kevent(efd, event, 2, nullptr, 0, nullptr);
#endif
        if(pending_count) {
            clear_pending(this);
        }
        LOGD(DEVENT, "%p closed %d\n", this, this->fd);
        close(this->fd);
    }

    this->fd = fd;
    if(fd > 0) {
        LOGD(DEVENT, "%p set fd: %d\n", this, fd);
        SetSocketUnblock(fd);
        auto ev = events;
        events = RW_EVENT::NONE;
        setEvents(ev);
    } else {
        events = RW_EVENT::NONE;
    }
}

int Ep::getFd() const {
    return fd;
}

void Ep::setEvents(RW_EVENT events) {
    if(events == this->events){
        return;
    }
    if (getFd() >= 0) {
#ifdef __linux__
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLHUP | EPOLLERR;
        if(!!(events & RW_EVENT::READ)){
            event.events |= EPOLLIN | EPOLLRDHUP;
        }
        if(!!(events & RW_EVENT::WRITE)){
            event.events |= EPOLLOUT;
        }
        int ret = epoll_ctl(efd, EPOLL_CTL_MOD, getFd(), &event);
        if (ret && errno == ENOENT) {
            ret = epoll_ctl(efd, EPOLL_CTL_ADD, getFd(), &event);
            if(ret){
                LOGE("epoll_ctl add failed:%s\n", strerror(errno));
                return;
            }
        }else if(ret){
            LOGE("epoll_ctl mod failed:%s\n", strerror(errno));
            return;
        }
#endif
#ifdef __APPLE__
        struct kevent event[3];
        int count = 0;
        if(!!(events & RW_EVENT::READ)){
            EV_SET(&event[count++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void*)(intptr_t)this);
        }else if(!!(this->events & RW_EVENT::READ)){
            EV_SET(&event[count++], fd, EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0, (void*)(intptr_t)this);
        }
        if(!!(events & RW_EVENT::WRITE)){
            EV_SET(&event[count++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void*)(intptr_t)this);
        }else if(!!(this->events & RW_EVENT::WRITE)){
            EV_SET(&event[count++], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, (void*)(intptr_t)this);
        }
        //EV_SET(&event[count++], fd, EVFILT_EXCEPT, EV_ADD | EV_ENABLE | EV_CLEAR, 0, 0, (void*)(intptr_t)this);
        int ret = kevent(efd, event, count, nullptr, 0, nullptr);
        if(ret < 0){
            LOGE("kevent failed %d:%s\n", efd, strerror(errno));
            return;
        }
#endif
        if(events != this->events) {
            assert(int(events) <= 3);
            LOGD(DEVENT, "modify event %d: %s --> %s\n", getFd(), events_string[int(this->events)], events_string[int(events)]);
        }
        this->events = events;
    }
}

void Ep::addEvents(RW_EVENT events){
    return setEvents(this->events | events);
}

void Ep::delEvents(RW_EVENT events){
    return setEvents(this->events & ~events);
}

void Ep::setNone(){
    if(fd < 0){
        return;
    }
    events = RW_EVENT::NONE;
#ifdef __linux__
    epoll_ctl(efd, EPOLL_CTL_DEL, fd, nullptr);
#endif
#ifdef __APPLE__
    struct kevent event[2];
    EV_SET(&event[0], fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
    EV_SET(&event[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
    kevent(efd, event, 2, nullptr, 0, nullptr);
#endif
    LOGD(DEVENT, "remove event %d: %s\n", fd, events_string[int(events)]);
}

RW_EVENT Ep::getEvents(){
    return this->events;
}

int Ep::checkSocket(const char* msg) const{
    return Checksocket(getFd(), msg);
}

int event_loop(uint32_t timeout_ms){
    int c;
#if __linux__
    struct epoll_event events[MAX_LOOP_EVENTS];
    if ((c = epoll_wait(efd, events, MAX_LOOP_EVENTS, timeout_ms)) <= 0) {
        if (c != 0 && errno != EINTR) {
            LOGE("epoll_wait: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    //epoll已把同一fd的事件合并成一条，直接追加即可
    for(int i = 0; i < c; ++i){
        Ep *ep = (Ep *)events[i].data.ptr;
        RW_EVENT event = convertEpoll(events[i].events);
        LOGD(DEVENT, "pending event %d: %s\n", ep->getFd(), events_string[int(event)]);
        push_pending(ep, event);
    }
#endif
#if __APPLE__
    struct kevent events[MAX_LOOP_EVENTS];
    struct timespec timeout{timeout_ms/1000, (timeout_ms%1000)*1000000};
    if((c = kevent(efd, nullptr, 0, events, MAX_LOOP_EVENTS, &timeout)) <= 0){
        if (c != 0 && errno != EINTR) {
            LOGE("kevent: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    for(int i = 0; i < c; ++i){
        Ep *ep = (Ep*)events[i].udata;
        if (events[i].filter == EVFILT_SIGNAL) {
            (ep->*ep->handleEvent)((RW_EVENT)events[i].ident);
            continue;
        }
        RW_EVENT event = convertKevent(events[i]);
        LOGD(DEVENT, "pending event %d: %s\n", ep->getFd(), events_string[int(event)]);
        push_pending(ep, event);
    }
#endif
    for(size_t i = 0; i < pending_count; ++i){
        if(pending_events[i].event == RW_EVENT::NONE){
            continue;
        }
        Ep *ep = pending_events[i].ep;
        if(!!(pending_events[i].event & RW_EVENT::READEOF) && !(ep->events & RW_EVENT::READ)){
            LOGD(DEVENT, "filter READEOF without listen READ: %d\n", ep->getFd());
            pending_events[i].event = pending_events[i].event & ~RW_EVENT::READEOF;
            if(pending_events[i].event == RW_EVENT::NONE){
                ep->setNone();
                continue;
            }
        }
        LOGD(DEVENT, "handle event %p, %d: %s\n", ep, ep->getFd(), events_string[int(pending_events[i].event)]);
        (ep->*ep->handleEvent)(pending_events[i].event);
    }
    pending_count = 0;
    return c;
}


Sign::Sign():Ep(-1) {
#if __linux__
    sigset_t mask;
    sigemptyset(&mask);
    setFd(signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC));
#endif
    handleEvent = (void (Ep::*)(RW_EVENT))&Sign::defaultHE;
}


int Sign::add(int sig, sig_t handler) {
    sigmap.emplace(sig, handler);
#if __APPLE__
    signal(sig, SIG_IGN);
    struct kevent sigevent;
    EV_SET(&sigevent, sig, EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, this);
    return kevent(efd, &sigevent, 1, nullptr, 0, nullptr);
#endif
#if __linux__
    sigset_t mask;
    sigemptyset(&mask);
    for(auto& i: sigmap){
        sigaddset(&mask, i.first);
    }
    sigprocmask(SIG_BLOCK, &mask, NULL);
    addEvents(RW_EVENT::READ);
    return signalfd(getFd(), &mask, SFD_NONBLOCK | SFD_CLOEXEC);
#endif
}

void Sign::defaultHE(RW_EVENT events) {
#if __APPLE__
    int signal = int(events);
#endif
#if __linux__
    assert(events == RW_EVENT::READ);
    (void)events;
    struct signalfd_siginfo info;
    ssize_t ret = read(getFd(), &info, sizeof(info));
    if(ret != sizeof(info)){
        LOGE("read signalfd failed: %s\n", strerror(errno));
        return;
    }
    int signal = info.ssi_signo;
#endif
    if(sigmap.count(signal)){
        sigmap[signal](signal);
    }
}

Sign::~Sign() {
    for(auto& i: sigmap){
        signal(i.first, SIG_DFL);
#if __APPLE__
        struct kevent sigevent;
        EV_SET(&sigevent, i.first, EVFILT_SIGNAL, EV_DELETE, 0, 0, nullptr);
        kevent(efd, &sigevent, 1, nullptr, 0, nullptr);
#endif
    }
}
