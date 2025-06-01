#ifndef GUEST_TPROXY_H__
#define GUEST_TPROXY_H__

#include "guest.h"

#include <memory>

class Guest_tproxy: public Guest {
public:
    bool inited = false;
    explicit Guest_tproxy(int fd, sockaddr_storage* src);
    explicit Guest_tproxy(int fd, sockaddr_storage* src, sockaddr_storage* dst, Buffer&& bb, std::function<void(Server*)> df);
    void push_data(Buffer&& bb) {
        DataProc(bb);
    }
};

bool operator<(const sockaddr_storage& a, const sockaddr_storage& b);

class Tproxy_server: public Ep {
    std::map<sockaddr_storage, Guest_tproxy*> tps;
    virtual void tcpHE(RW_EVENT events) {
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
            LOGD(DNET, "accept %d from tcp: %s\n", clsk, storage_ntoa(&hisaddr));
            SetTcpOptions(clsk, &hisaddr);
            new Guest_tproxy(clsk, &hisaddr);
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
            auto guest = new Guest_tproxy(clsk, &hisaddr, &myaddr, std::move(bb), [this, hisaddr](Server*){
                tps.erase(hisaddr);
            });
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
        int protocol;
        socklen_t socklen = sizeof(protocol);
        if(getsockopt(fd, SOL_SOCKET, SO_PROTOCOL, &protocol, &socklen)) {
            LOGF("failed to get protocol: %s\n", strerror(errno));
        }
        sockaddr_storage myaddr;
        socklen = sizeof(myaddr);
        if(getsockname(fd, (sockaddr*)&myaddr, &socklen)) {
            LOGF("failed to get sockname: %s\n", strerror(errno));
        }
        if(protocol == IPPROTO_TCP) {
            handleEvent = (void (Ep::*)(RW_EVENT))&Tproxy_server::tcpHE;
        }else if(protocol == IPPROTO_UDP) {
            handleEvent = (void (Ep::*)(RW_EVENT))&Tproxy_server::udpHE;
        }else {
            LOGF("unknown protocol: %d\n", protocol);
        }
    }
};

#endif
