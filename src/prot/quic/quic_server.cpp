//
// Created by 周威 on 2022/4/18.
//
#define __APPLE_USE_RFC_3542
#include "quic_server.h"
#include "req/guest3.h"
#include "req/guest_sni.h"

#include <unistd.h>

static ssize_t recvwithaddr(int fd, void* buff, size_t buflen,
                            sockaddr_storage* myaddr, sockaddr_storage* hisaddr) {
    struct iovec iov;
    iov.iov_base = buff;
    iov.iov_len = buflen;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    memset(hisaddr, 0, sizeof(*hisaddr));
    msg.msg_name = hisaddr;
    msg.msg_namelen = sizeof(*hisaddr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    char controlbuf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(struct in_pktinfo))];
    msg.msg_control = controlbuf;
    msg.msg_controllen = sizeof(controlbuf);

    ssize_t ret = recvmsg(fd, &msg, 0);
    if(ret < 0){
        LOGE("recvfrom error: %s\n", strerror(errno));
        return ret;
    }
    memset(myaddr, 0, sizeof(*myaddr));
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO) {
            struct in6_pktinfo *info6 = (struct in6_pktinfo *) CMSG_DATA(cmsg);
            sockaddr_in6* myaddr6 = (sockaddr_in6*)myaddr;
            myaddr6->sin6_family = AF_INET6;
            myaddr6->sin6_addr = info6->ipi6_addr;
            myaddr6->sin6_port = htons(opt.quic.port);
        } else if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *info = (struct in_pktinfo *) CMSG_DATA(cmsg);
            sockaddr_in* myaddr4 = (sockaddr_in*)myaddr;
            myaddr4->sin_family = AF_INET;
            myaddr4->sin_addr = info->ipi_addr;
            myaddr4->sin_port = htons(opt.quic.port);
        } else {
            LOGE("unknown level: %d or type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
            return -1;
        }
    }
    if(myaddr->ss_family == AF_UNSPEC) {
        LOGE("can't get IP_PKTINFO\n");
        return -1;
    }
    return ret;
}

void Quic_server::defaultHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        LOGE("Quic server: %d\n", checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ)) {
        char buff[max_datagram_size];
        sockaddr_storage myaddr, hisaddr;

        ssize_t ret = recvwithaddr(getFd(), buff, max_datagram_size, &myaddr, &hisaddr);
        if(ret < 0){
            LOGE("recvfrom error: %s\n", strerror(errno));
            return;
        }
        PushData(&myaddr, &hisaddr, buff, ret);
    } else {
        LOGE("unknown error\n");
        return;
    }
}

void Quic_server::PushData(const sockaddr_storage* myaddr, const sockaddr_storage* hisaddr,
                           const void *buff, size_t len) {
    quic_pkt_header header;
    header.dcid.resize(QUIC_CID_LEN);
    int body_len = unpack_meta(buff, len, &header);
    if (body_len < 0 || body_len > (int)len) {
        LOGE("QUIC meta unpack failed, disacrd it, body_len: %d, len: %d\n", body_len, (int)len);
        return;
    }
    auto r = rwers.find(header.dcid);
    if(r != rwers.end()){
        LOGD(DQUIC, "duplicated packet: %s vs %s, may be migration?\n",
            storage_ntoa(hisaddr), dumpDest(r->second->getSrc()).c_str());
        iovec iov{(void*)buff, len};
        r->second->walkPackets(&iov, 1);
    }else if(header.type == QUIC_PACKET_INITIAL){
        int clsk = ListenUdp(myaddr, nullptr);
        if (clsk < 0) {
            LOGE("ListenNet %s:%d, failed: %s\n", opt.quic.hostname, (int)opt.quic.port, strerror(errno));
            return;
        }
        socklen_t socklen = (hisaddr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (::connect(clsk, (sockaddr *)hisaddr, socklen) < 0) {
            LOGE("connect %s failed: %s\n", storage_ntoa(hisaddr), strerror(errno));
            return;
        }
        SetUdpOptions(clsk, hisaddr);
        auto qrwer = std::make_shared<QuicRWer>(clsk, hisaddr, ctx, this);
        auto guest = new Guest3(qrwer);
        guest->AddInitData(buff, len);
    }else if(header.type == QUIC_PACKET_1RTT){
        if(len < 42){
            LOG("QUIC packet 1RTT too short: %zd, will not trigger reset\n", len);
            return;
        }
        std::string token = sign_cid(header.dcid);
        if(token.empty()){
            return;
        }
        char stateless[41];
        stateless[0] = 0x43;
        memcpy(stateless + sizeof(stateless) - QUIC_TOKEN_LEN, token.data(), QUIC_TOKEN_LEN);

        int fd = ListenUdp(myaddr, nullptr);
        socklen_t socklen = (hisaddr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        int ret = sendto(fd, stateless, sizeof(stateless), 0, (sockaddr *)hisaddr, socklen);
        ::close(fd);
        if(ret < 0){
            LOGE("sendto %s failed: %s\n", storage_ntoa(hisaddr), strerror(errno));
            return;
        }
        LOGD(DQUIC, "send stateless reset for %s\n", dumpHex(header.dcid.c_str(), header.dcid.size()).c_str());
    }
}

void Quic_sniServer::defaultHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        LOGE("Quic server: %d\n", checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ)) {
        char buff[max_datagram_size];
        sockaddr_storage myaddr, hisaddr;

        ssize_t ret = recvwithaddr(getFd(), buff, max_datagram_size, &myaddr, &hisaddr);
        if(ret < 0){
            LOGE("recvfrom error: %s\n", strerror(errno));
            return;
        }

        int clsk = ListenUdp(&myaddr, nullptr);
        if (clsk < 0) {
            LOGE("ListenNet failed: %s\n", strerror(errno));
            return;
        }
        socklen_t socklen = (hisaddr.ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if (::connect(clsk, (sockaddr *)&hisaddr, socklen) < 0) {
            LOGE("connect failed: %s\n", strerror(errno));
            return;
        }
        SetUdpOptions(clsk, &hisaddr);
        auto guest = new Guest_sni(clsk, &hisaddr, nullptr);
        guest->sniffer_quic({buff, (size_t)ret});
    } else {
        LOGE("unknown error\n");
        return;
    }
}
