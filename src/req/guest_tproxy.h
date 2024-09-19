#ifndef GUEST_TPROXY_H__
#define GUEST_TPROXY_H__

#include "guest.h"


class Guest_tproxy: public Guest {
    int protocol;
public:
    explicit Guest_tproxy(int fd, const sockaddr_storage* src);
    explicit Guest_tproxy(int fd, const sockaddr_storage*, Buffer&& bb);
};

class Tproxy_server: public Ep {
    sockaddr_storage myaddr;
    virtual void tcpHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("tcp server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_storage myaddr;
            socklen_t temp = sizeof(myaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&myaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&myaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            SetTcpOptions(clsk, &myaddr);
            new Guest_tproxy(clsk, &myaddr);
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
            Buffer bb{BUF_LEN};
            socklen_t socklen = sizeof(hisaddr);
            int ret = recvfrom(getFd(), bb.mutable_data(), BUF_LEN, 0, (sockaddr*)&hisaddr, &socklen);
            if(ret < 0) {
                LOGE("failed recv udp packet: %s\n", strerror(errno));
                return;
            }
            bb.truncate(ret);
            int clsk = ListenUdp(&myaddr, nullptr);
            if(clsk < 0) {
                LOGE("failed to recreate udp socket: %d\n", getFd());
                return;
            }
            if(::connect(clsk, (sockaddr*)&hisaddr, socklen)) {
                LOGE("failed to connect peer: %s\n", strerror(errno));
                return;
            }
            SetUdpOptions(clsk, &hisaddr);
            new Guest_tproxy(clsk, &hisaddr, std::move(bb));
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
