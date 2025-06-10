//
// Created by choury on 2021/4/21.
//
#include "network_notify.h"
#include "common/common.h"
#include "prot/ep.h"

#include <functional>
#include <memory>


class Notifier: public Ep {
    std::function<void()> cb;
public:
    explicit Notifier(int fd, std::function<void()> cb):
    Ep(fd), cb(std::move(cb)) {
        LOGD(DNET, "create notifiler: %p [%d]\n", this, fd);
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Notifier::defaultHE;
    }

    void setcb(std::function<void()> cb) {
        this->cb = std::move(cb);
    }

    void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            checkSocket(__PRETTY_FUNCTION__);
            delete this;
            return;
        }
        if(!!(events & RW_EVENT::READ)){
            have_network_changed(getFd())? cb() : void();
        }
        if(!!(events & RW_EVENT::READEOF)) {
            LOGE("network notifiler closed\n");
            delete this;
            return;
        }
    }
    virtual ~Notifier() override {
        LOGD(DNET, "notifiler destoried: %p\n", this);
    }
};

static std::shared_ptr<Notifier> notifier;

int register_network_change_cb(network_notify_callback cb) {
    if(notifier != nullptr) {
        notifier->setcb(cb);
        return 0;
    }
    int fd = create_notifier_fd();
    if(fd < 0) {
        LOGE("create network notifiler failed");
        return -1;
    }
    notifier = std::make_shared<Notifier>(fd, cb);
    return 0;
}
