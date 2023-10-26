#include "guest_sni.h"
#include "prot/tls.h"
#include "prot/quic/quic_pack.h"
#include "misc/util.h"
#include "misc/net.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "res/responser.h"

#include <stdlib.h>
#include <inttypes.h>
#include <sstream>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx):Guest(fd, addr, ctx){
    assert(ctx == nullptr);
    rwer->SetReadCB(std::bind(&Guest_sni::sniffer, this, _1));
    Http_Proc = &Guest_sni::AlwaysProc;
    std::stringstream ss;
    ss << "Sproxy/" << getVersion()
       << " (Build " << getBuildTime() << ") "
       <<"(" << getDeviceInfo() << ")";
    user_agent = ss.str();
}

Guest_sni::Guest_sni(std::shared_ptr<RWer> rwer, std::string host, std::string ua):
        Guest(rwer), host(std::move(host)), user_agent(std::move(ua))
{
    if(std::dynamic_pointer_cast<PMemRWer>(rwer)) {
        rwer->SetReadCB(std::bind(&Guest_sni::sniffer_quic, this, _1));
    } else if(std::dynamic_pointer_cast<MemRWer>(rwer)) {
        rwer->SetReadCB(std::bind(&Guest_sni::sniffer, this, _1));
    } else {
        LOGF("Guest_sni: rwer type error\n");
    }
    Http_Proc = &Guest_sni::AlwaysProc;
}

size_t Guest_sni::sniffer(const Buffer& bb) {
    char *hostname = nullptr;
    defer(free, hostname);
    int ret = parse_tls_header((const char*)bb.data(), bb.len, &hostname);
    if(ret == -1) {
        return bb.len;
    }
    if(ret < 0) {
        if(!host.empty()) {
            hostname = strdup(host.c_str());
        } else {
            deleteLater(SNI_HOST_ERR);
            return 0;
        }
    }
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s:%d" CRLF CRLF, hostname, 443);
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    header->set("User-Agent", user_agent + " SEQ/" + std::to_string(header->request_id));
    LOGD(DHTTP, "<guest_sni> ReqProc %" PRIu32 " %s\n", header->request_id, header->geturl().c_str());
    auto req = std::make_shared<HttpReq>(header,std::bind(&Guest_sni::response, this, nullptr, _1),
                                         [this]{ rwer->Unblock(0);});

    statuslist.emplace_back(ReqStatus{req, nullptr, nullptr, 0});
    distribute(req, this);
    rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1));
    return bb.len;
}

size_t Guest_sni::sniffer_quic(const Buffer& bb) {
#ifdef HAVE_QUIC
    quic_pkt_header header;
    int body_len = unpack_meta(bb.data(), bb.len, &header);
    if (body_len < 0 || body_len > (int)bb.len) {
        LOGE("QUIC sni meta unpack failed, disacrd it: %d\n", body_len);
        deleteLater(SNI_HOST_ERR);
        return 0;
    }
    if(header.type != QUIC_PACKET_INITIAL) {
        LOGE("QUIC sni packet type is not initial, discard it: 0x%x\n", header.type);
        deleteLater(SNI_HOST_ERR);
        return 0;
    }
    quic_secret secret;
    if(quic_generate_initial_key(1, header.dcid.c_str(), header.dcid.size(), &secret) < 0){
        LOGE("Quic sni faild to generate initial key\n");
        deleteLater(SNI_HOST_ERR);
        return 0;
    }
    auto buffer = std::make_unique<char[]>(body_len);
    size_t length = 0;
    size_t max_off = 0;
    auto frames = decode_packet(bb.data(), body_len, &header, &secret);
    for(const auto& frame: frames) {
        if(frame->type != QUIC_FRAME_CRYPTO){
            continue;
        }
        length += frame->crypto.length;
        memcpy(buffer.get() + frame->crypto.offset, frame->crypto.buffer.data, frame->crypto.length);
        if(frame->crypto.offset + frame->crypto.length > max_off) {
            max_off = frame->crypto.offset + frame->crypto.length;
        }
    }
    if(max_off == 0 || max_off < length) {
        LOGE("Quic sni faild to get ClientHello: %zd vs %zd\n", max_off, length);
        deleteLater(SNI_HOST_ERR);
        return 0;
    }
    char *hostname = nullptr;
    defer(free, hostname);
    int ret = parse_client_hello((const char*)buffer.get(), length, &hostname);
    if(ret <= 0) {
        LOGE("Quic faild to parse sni from clientHello: %d\n", ret);
        deleteLater(SNI_HOST_ERR);
        return 0;
    }
    {
        char headstr[HEADLENLIMIT];
        int slen = snprintf(headstr, sizeof(headstr), "CONNECT %s:%d" CRLF "Protocol: udp" CRLF CRLF, hostname, 443);
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(headstr, slen);
        header->set("User-Agent", user_agent + " SEQ/" + std::to_string(header->request_id));
        LOGD(DHTTP, "<guest_sni> ReqProc %" PRIu32 " %s\n", header->request_id, header->geturl().c_str());
        auto req = std::make_shared<HttpReq>(header,std::bind(&Guest_sni::response, this, nullptr, _1),
                                            [this]{ rwer->Unblock(0);});

        statuslist.emplace_back(ReqStatus{req, nullptr, nullptr, 0});
        distribute(req, this);
        rx_bytes += bb.len;
        req->send(bb.clone());
    }
    rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1));
#endif
    return bb.len;
}

void Guest_sni::response(void*, std::shared_ptr<HttpRes> res){
    assert(statuslist.size() == 1);
    ReqStatus& status = statuslist.front();
    assert(status.res == nullptr);
    status.res = res;
    status.flags |= HTTP_NOEND_F;
    res->attach([this, &status](ChannelMessage& msg){
        assert(!statuslist.empty());
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            HttpLog(rwer->getPeer(), status.req->header, header);
            if(memcmp(header->status, "200", 3) == 0){
                rwer->Unblock(0);
                return 1;
            }else {
                deleteLater(PEER_LOST_ERR);
                return 0;
            }
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(msg.signal);
            return 0;
        }
        return 0;
    }, [this]{ return  rwer->cap(0); });
}
