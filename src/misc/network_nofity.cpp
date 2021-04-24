//
// Created by 周威 on 2021/4/21.
//
#include "network_notify.h"
#include "common/common.h"
#include "prot/ep.h"
#include "misc/net.h"

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <functional>

class Notifier: public Ep {
    std::function<void(void)> cb;
public:
    explicit Notifier(int fd, std::function<void(void)> cb): Ep(fd), cb(std::move(cb)){
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Notifier::defaultHE;
    }

    void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            checkSocket(__PRETTY_FUNCTION__);
            delete this;
            return;
        }
        if(!!(events & RW_EVENT::READ)){
            char buff[1024];
            while(read(getFd(), buff, sizeof(buff))> 0);
            cb();
        }
        if(!!(events & RW_EVENT::READEOF)) {
            LOGE("pipe closed\n");
            delete this;
            return;
        }
    }
};

int register_network_change_cb(network_notify_callback cb) {
    int pipefd[2];
    if(pipe(pipefd) < 0){
        LOGE("pipe failed: %s\n", strerror(errno));
        return -1;
    }
    new Notifier(pipefd[0], cb);
    SetSocketUnblock(pipefd[1]);
    notify_network_change(pipefd[1]);
    return 0;
}
