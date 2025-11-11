#ifndef GUEST_TPROXY_H__
#define GUEST_TPROXY_H__

#include "guest.h"
#include "prot/netio.h"

class Guest_tproxy: public Guest {
public:
    bool inited = false;
    explicit Guest_tproxy(int fd, sockaddr_storage* src);
    explicit Guest_tproxy(int fd, sockaddr_storage* src,
        sockaddr_storage* dst, Buffer&& bb, std::function<void(Server*)> df);
    explicit Guest_tproxy(std::shared_ptr<RWer> rwer,
        const std::string& rproxy, const Destination* dst, std::function<void(Server*)> df);
    void push_data(Buffer&& bb) {
        DataProc(bb);
    }
};

bool operator<(const sockaddr_storage& a, const sockaddr_storage& b);

class Tproxy_server: public Ep, public std::enable_shared_from_this<Tproxy_server> {
    int family;
    std::string rproxy;
    Destination target;
    std::map<sockaddr_storage, Guest_tproxy*> tps;
    virtual void acceptHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("tcp server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_storage hisaddr;
            socklen_t temp = sizeof(hisaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&hisaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&hisaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }
            if(family == AF_UNIX) {
                SetUnixOptions(clsk, &hisaddr);
                //use getsockname to pad unix path
                socklen_t addr_len = sizeof(hisaddr);
                if(getsockname(clsk, (sockaddr*)&hisaddr, &addr_len)){
                    LOGE("failed to getsockname <%d>: %s\n", clsk, strerror(errno));
                }else{
                    PadUnixPath(&hisaddr, addr_len);
                }
            }else{
                SetTcpOptions(clsk, &hisaddr);
            }
            LOGD(DNET, "accept %d from %s\n", clsk, storage_ntoa(&hisaddr));
            if(rproxy.empty()) {
#if __linux__
                new Guest_tproxy(clsk, &hisaddr);
#else
                LOGF("tproxy without rproxy is not supported");
#endif
            } else {
                auto rwer = std::make_shared<StreamRWer>(
                    clsk, &hisaddr, IRWerCallback::create()->onError([](int, int){}));
                new Guest_tproxy(rwer, rproxy, &target, nullptr);
            }
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
    virtual void udpHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("udp server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            sockaddr_storage hisaddr;
            sockaddr_storage myaddr;
            Buffer bb{BUF_LEN};
            socklen_t socklen = sizeof(hisaddr);
            int ret = recvwithaddr(getFd(), bb.mutable_data(), BUF_LEN, &myaddr, &hisaddr);
            if(ret < 0) {
                LOGE("failed recv udp packet: %s\n", strerror(errno));
                return;
            }
            if(isBroadcast(&myaddr)){
                return;
            }
            bb.truncate(ret);
            if(tps.count(hisaddr)) {
                tps[hisaddr]->push_data(std::move(bb));
                return;
            }
            listenOption ops = {
                .disable_defer_accepct = true,
                .enable_ip_transparent = true,
            };
            int clsk = ListenUdp(&myaddr, &ops);
            if(clsk < 0) {
                LOGE("failed to recreate udp socket: %s\n", storage_ntoa(&myaddr));
                return;
            }
            if(::connect(clsk, (sockaddr*)&hisaddr, socklen)) {
                LOGE("failed to connect peer [%s]: %s\n", storage_ntoa(&hisaddr), strerror(errno));
                return;
            }
            LOGD(DNET, "connect udp %d to %s\n", clsk, storage_ntoa(&hisaddr));
            SetUdpOptions(clsk, &hisaddr);
            auto clean = [weak_self = weak_from_this(), hisaddr](Server*){
                auto self = weak_self.lock();
                if(!self) {
                    return;
                }
                self->tps.erase(hisaddr);
            };
            Guest_tproxy* guest = nullptr;
            if(rproxy.empty()) {
#if __linux__
                guest = new Guest_tproxy(clsk, &hisaddr, &myaddr, std::move(bb), clean);
#else
                LOGF("tproxy without rproxy is not supported");
#endif
            }else {
                auto rwer = std::make_shared<PacketRWer>(
                    clsk, &hisaddr, IRWerCallback::create()->onError([](int, int){}));
                guest = new Guest_tproxy(rwer, rproxy, &target, clean);
                guest->push_data(std::move(bb));
            }
            if(guest->inited) {
                tps[hisaddr] = guest;
            }
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    Tproxy_server(int fd): Ep(fd) {
        setEvents(RW_EVENT::READ);

        int type;
        socklen_t socklen = sizeof(type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &socklen)) {
            LOGF("failed to get socket type: %s\n", strerror(errno));
        }

        sockaddr_storage myaddr;
        socklen = sizeof(myaddr);
        if (getsockname(fd, (sockaddr*)&myaddr, &socklen)) {
            LOGF("failed to get sockname: %s\n", strerror(errno));
        }
        family = myaddr.ss_family;

        if (type == SOCK_STREAM) {
            handleEvent = (void (Ep::*)(RW_EVENT))&Tproxy_server::acceptHE;
        } else if (type == SOCK_DGRAM) {
            handleEvent = (void (Ep::*)(RW_EVENT))&Tproxy_server::udpHE;
        } else {
            LOGF("unknown socket type/family: family=%d, type=%d\n", family, type);
        }
    }
    Tproxy_server(int fd, const std::string& rproxy, const Destination& target): Tproxy_server(fd){
        this->rproxy = rproxy;
        this->target = target;
    }
};

#endif
