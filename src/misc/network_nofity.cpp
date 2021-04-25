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
    const int sender;
    explicit Notifier(int pipefd[2], std::function<void(void)> cb):
    Ep(pipefd[0]), cb(std::move(cb)), sender(pipefd[1]){
        setEvents(RW_EVENT::READ);
        SetSocketUnblock(sender);
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
    virtual ~Notifier(){
        close(sender);
    }
};

static Notifier* notifier = nullptr;

int register_network_change_cb(network_notify_callback cb) {
    if(notifier == nullptr){
        int pipefd[2];
        if(pipe(pipefd) < 0){
            LOGE("pipe failed: %s\n", strerror(errno));
            return -1;
        }
        notifier = new Notifier(pipefd, cb);
    }
    notify_network_change(notifier->sender);
    return 0;
}
