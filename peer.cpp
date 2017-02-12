#include "peer.h"

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


ssize_t Peer::Write(const void* buff, size_t size, void* index) {
    return Write(p_memdup(buff, size), size, index);
}

ssize_t Peer::Write(void* buff, size_t size, void*) {
    return push_buff(buff, size);
}

void Peer::wait(void*){

}

void Peer::writedcb(void*) {
    updateEpoll(events | EPOLLIN);
}

int32_t Peer::bufleft(void*) {
    if(writelen >= 1024*1024)
        return 0;
    else
        return BUF_LEN;
}



void Peer::clean(uint32_t errcode, void*) {
    if(fd > 0) {
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Peer::closeHE;
    }else{
        delete this;
    }
}
