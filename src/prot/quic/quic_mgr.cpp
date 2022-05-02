//
// Created by 周威 on 2022/4/18.
//
#include "quic_mgr.h"
#include "req/guest3.h"

void QuicMgr::PushDate(int fd, const sockaddr_storage* addr, SSL_CTX *ctx, const void *buff, size_t len) {
    quic_pkt_header header;
    header.dcid.resize(QUIC_CID_LEN);
    int body_len = unpack_meta(buff, len, &header);
    if (body_len < 0 || body_len > (int)len) {
        LOGE("QUIC meta unpack failed, disacrd it\n");
        return;
    }
    auto r = rwers.find(header.dcid);
    if(r != rwers.end()){
        LOGD(DQUIC, "duplicated packet: %s, may be migration?\n", header.dcid.c_str());
        r->second->walkPackets(buff, len);
    }else if(header.type == QUIC_PACKET_INITIAL){
        int clsk = ListenNet(SOCK_DGRAM, opt.CPORT);
        if (clsk < 0) {
            LOGE("ListenNet failed: %s\n", strerror(errno));
            return;
        }
        socklen_t temp = sizeof(sockaddr_storage);
        if (::connect(clsk, (sockaddr *)addr, temp) < 0) {
            LOGE("connect failed: %s\n", strerror(errno));
            return;
        }
        SetUdpOptions(clsk, addr);

        auto guest = new Guest3(clsk, addr, ctx, this);
        guest->AddInitData(buff, len);
    }else if(header.type == QUIC_PACKET_1RTT){
        if(len < 42){
            LOG("QUIC packet 1RTT too short: %zd, will not trigger reset\n", len);
            return;
        }
        std::string token = sign_cid(header.dcid);
        if(token == ""){
            return;
        }
        char stateless[41];
        stateless[0] = 0x43;
        memcpy(stateless + sizeof(stateless) - QUIC_TOKEN_LEN, token.data(), QUIC_TOKEN_LEN);

        socklen_t len = (addr->ss_family == AF_INET)? sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
        if(sendto(fd, stateless, sizeof(stateless), 0, (sockaddr *)addr, len) < 0){
            LOGE("sendto failed: %s\n", strerror(errno));
            return;
        }
        LOGD(DQUIC, "send stateless reset for %s\n", dumpHex(header.dcid.c_str(), header.dcid.size()).c_str());
    }
}
