#include "peer.h"
#include "guest.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>


Peer::Peer(int fd):Con(fd) {
}


Peer::~Peer() {
    while(!write_queue.empty()){
        p_free(write_queue.front().buff);
        write_queue.pop();
    }
}

ssize_t Peer::push_buff(void* buff, size_t size) {
    if(size == 0) {
        p_free(buff);
        return 0;
    }
    write_block wb={buff, size, 0};
    write_queue.push(wb);
    writelen += size;

    updateEpoll(events | EPOLLOUT);
    return size;
}

ssize_t Peer::Read(void* buff, size_t size) {
    return read(fd, buff, size);
}

ssize_t Peer::Write(const void* buff, size_t size) {
    return write(fd, buff, size);
}

int Peer::Write_buff() {
    bool writed = false;
    while(!write_queue.empty()){
        write_block *wb = &write_queue.front();
        ssize_t ret = Write((char *)wb->buff + wb->wlen, wb->len - wb->wlen);

        if (ret <= 0) {
            return ret;
        }

        writed = true;
        writelen -= ret;
        assert(ret + wb->wlen <= wb->len);
        if ((size_t)ret + wb->wlen == wb->len) {
            p_free(wb->buff);
            write_queue.pop();
        } else {
            wb->wlen += ret;
            return WRITE_INCOMP;
        }
    }

    updateEpoll(EPOLLIN);
    return writed ? WRITE_COMPLETE : WRITE_NOTHING;
}


ssize_t Peer::Write(const void* buff, size_t size, uint32_t id) {
    return Write(p_memdup(buff, size), size, id);
}

ssize_t Peer::Write(void* buff, size_t size, uint32_t) {
    return push_buff(buff, size);
}

void Peer::wait(uint32_t){

}

void Peer::writedcb(uint32_t) {
    updateEpoll(events | EPOLLIN);
}

int32_t Peer::bufleft(uint32_t) {
    if(writelen >= 1024*1024)
        return 0;
    else
        return BUF_LEN;
}



void Peer::clean(uint32_t errcode, uint32_t) {
    if(fd > 0) {
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
    }else{
        delete this;
    }
}

struct tick_n{
    void (* func)(void *);
    void *arg;
};

struct tick_v{
    const char *func_name;
    uint32_t interval;
    uint32_t last_tick;
};


class tick_n_cmp{
public:
    bool operator()(const struct tick_n& a, const struct tick_n& b) const{
        if(a.func == b.func){
            return a.arg < b.arg;
        }else{
            return a.func < b.func;
        }
    }
};

std::map<tick_n, tick_v, tick_n_cmp> callfunc_map;

void add_job_real(job_func func, const char *func_name, void *arg, uint32_t interval){
#ifndef NDEBUG
    if(callfunc_map.count(tick_n{func, arg})){
        LOGD(DTICK, "update a function %s for %p by %d\n", func_name, arg, interval);
    }else{
        LOGD(DTICK, "add a function %s for %p by %d\n", func_name, arg, interval);
    }
#endif
    callfunc_map[tick_n{func, arg}] = tick_v{func_name, interval, getmtime()};
}

void del_job_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    if(callfunc_map.count(tick_n{func, arg})){
        LOGD(DTICK, "del a function %s of %p\n", func_name, arg);
    }else{
        LOGD(DTICK, "del a function %s of %p not found\n", func_name, arg);
    }
#endif
    callfunc_map.erase(tick_n{func, arg});
}

uint32_t do_job(){
    uint32_t now = getmtime();
    uint32_t min_interval = 0xffffffff;
    std::vector<tick_n> tick_set;
    for(auto i=callfunc_map.begin(); i!= callfunc_map.end(); i++){
        uint32_t diff = now - i->second.last_tick;
        if(diff >= i->second.interval){
#ifndef NDEBUG
            LOGD(DTICK, "%s for %p ticked diff %u\n",
                 i->second.func_name, i->first.arg, diff );
#endif
            i->second.last_tick = now;
            tick_set.push_back(i->first);
        }
        uint32_t left = i->second.interval + i->second.last_tick - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    for(auto i:tick_set){
        i.func(i.arg);
    }
    return min_interval;
}
