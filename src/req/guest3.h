//
// Created by 周威 on 2022/3/18.
//

#ifndef SPROXY_GUEST3_H
#define SPROXY_GUEST3_H

#include "requester.h"
#include "prot/http3/http3.h"
#include "prot/quic/quicio.h"
#include "misc/net.h"
#include "misc/config.h"

#include <errno.h>

class Guest3: public Requester, public Http3Responser {
    struct ReqStatus{
        std::shared_ptr<HttpReq> req;
        std::shared_ptr<HttpRes> res;
        uint32_t flags;
    };

    std::map<uint64_t, ReqStatus> statusmap;
    uint64_t maxDataId = 0;
protected:
    virtual void Error(int ret, int code);
    virtual void deleteLater(uint32_t errcode) override;

    virtual void GoawayProc(uint64_t id) override;
    virtual void ReqProc(uint64_t id, HttpReqHeader* res)override;
    virtual void PushFrame(uint64_t id, PREPTR void* buff, size_t len)override;
    virtual void DataProc(uint64_t id, const void *data, size_t len)override;
    virtual void ErrProc(int errcode)override;
    virtual void Reset(uint64_t id, uint32_t code)override;
    virtual void ShutdownProc(uint64_t id)override;
    virtual uint64_t CreateUbiStream() override;

    void Send(uint64_t id ,const void* buff, size_t size);
    void RstProc(uint64_t id, uint32_t errcode);
    void Clean(uint64_t id, ReqStatus& status, uint32_t errcode);
public:
    explicit Guest3(int fd, sockaddr_storage* addr, SSL_CTX* ctx);
    virtual ~Guest3() override;

    virtual void response(void* index, std::shared_ptr<HttpRes> res) override;

    virtual void dump_stat(Dumper dp, void* param) override;
    std::shared_ptr<QuicRWer> getQuicRWer();
};

class Quic_server: public Ep {
    SSL_CTX *ctx = nullptr;

    std::map<std::string, std::weak_ptr<QuicRWer>> guests;
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Http server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            struct sockaddr_storage myaddr;
            socklen_t temp = sizeof(myaddr);
            memset(&myaddr, 0, temp);
            char buff[max_datagram_size];
            ssize_t ret = recvfrom(getFd(), buff, sizeof(buff), 0, (sockaddr*)&myaddr, &temp);
            if(ret < 0){
                LOGE("recvfrom error: %s\n", strerror(errno));
                return;
            }
            quic_pkt_header header;
            header.dcid.resize(QUIC_CID_LEN);
            int body_len = unpack_meta(buff, ret, &header);
            if (body_len < 0 || body_len > (int)ret) {
                LOGE("QUIC meta unpack failed, disacrd it\n");
                return;
            }
            if(guests.count(header.dcid) ) {
                auto qrwer = guests[header.dcid];
                if(qrwer.expired()){
                    //TODO:: send CONNECTION_REFUSED
                    LOGE("QUIC server get expired packet: %s\n", header.dcid.c_str());
                    return;
                }
                LOGD(DQUIC, "duplicated packet: %s, may be migration?\n", header.dcid.c_str());
                qrwer.lock()->walkPackets(buff, ret);
            }else if(header.type == QUIC_PACKET_INITIAL){
                int clsk = ListenNet(SOCK_DGRAM, opt.CPORT);
                if (clsk < 0) {
                    LOGE("ListenNet failed: %s\n", strerror(errno));
                    return;
                }
                if (::connect(clsk, (sockaddr *) &myaddr, temp) < 0) {
                    LOGE("connect failed: %s\n", strerror(errno));
                    return;
                }
                SetUdpOptions(clsk, &myaddr);

                auto guest = new Guest3(clsk, &myaddr, ctx);
                std::weak_ptr<QuicRWer> rwer = guest->getQuicRWer();
                //we should not handle stream frame here, so ConsumeRData is not needed.
                rwer.lock()->walkPackets(buff, ret);
                rwer.lock()->reorderData();
                guests[rwer.lock()->GetDCID()] = rwer;
                guests[header.dcid] = rwer;
            }else if(header.type == QUIC_PACKET_1RTT){
                //TODO: send stateless reset
            }
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Quic_server() override{
        if(ctx){
            SSL_CTX_free(ctx);
        }
    };
    Quic_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Quic_server::defaultHE;
    }
};

#endif //SPROXY_GUEST3_H
