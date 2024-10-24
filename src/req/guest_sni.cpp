#include "guest_sni.h"
#include "prot/tls.h"
#include "prot/quic/quic_pack.h"
#include "misc/util.h"
#include "misc/net.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "res/responser.h"
#include "common/version.h"

#include <stdlib.h>
#include <inttypes.h>
#include <sstream>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx):Guest(fd, addr, ctx){
    assert(ctx == nullptr);
    headless = true;
    rwer->SetReadCB([this](Buffer&& bb){return sniffer(std::move(bb));});
    Http_Proc = &Guest_sni::AlwaysProc;
    user_agent = generateUA(opt.ua, "", 0);
}

Guest_sni::Guest_sni(std::shared_ptr<RWer> rwer, std::string host, const char* ua):
        Guest(rwer), host(std::move(host))
{
    headless = true;
    if(ua) {
        user_agent = ua;
    }
    if(std::dynamic_pointer_cast<PMemRWer>(rwer)) {
        rwer->SetReadCB([this](Buffer&& bb){return sniffer_quic(std::move(bb));});
    } else if(std::dynamic_pointer_cast<MemRWer>(rwer)) {
        rwer->SetReadCB([this](Buffer&& bb){return sniffer(std::move(bb));});
    } else {
        LOGF("Guest_sni: rwer type error\n");
    }
    Http_Proc = &Guest_sni::AlwaysProc;
}

std::shared_ptr<HttpReq> Guest_sni::forward(const char *hostname, Protocol prot) {
    if(hostname == nullptr) {
        hostname = host.c_str();
    }
    if(hostname == nullptr || *hostname == '\0') {
        LOGE("Guest_sni: empty hostname\n");
        return nullptr;
    }
    char buff[HEADLENLIMIT];
    int slen;
    if(strchr(hostname, ':') && hostname[0] != '[') {
        //may be ipv6 without []
        slen = snprintf(buff, sizeof(buff), "CONNECT [%s]:%d" CRLF, hostname, 443);
    }else {
        slen = snprintf(buff, sizeof(buff), "CONNECT %s:%d" CRLF, hostname, 443);
    }
    if(prot == Protocol::UDP) {
        slen += snprintf(buff + slen, sizeof(buff) - slen, "Protocol: udp" CRLF);
    }
    slen += snprintf(buff + slen, sizeof(buff) - slen, CRLF);
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    if(header == nullptr) {
        LOGE("Guest_sni: UnpackHttpReq failed\n");
        return nullptr;
    }
    if(shouldNegotiate(header, this)) {
        LOGE("Guest_sni: avoid loop back\n");
        return nullptr;
    }
    header->set("User-Agent", generateUA(user_agent.c_str(), "", header->request_id));
    LOGD(DHTTP, "<guest_sni> ReqProc %" PRIu64 " %s\n", header->request_id, header->geturl().c_str());
    auto req = std::make_shared<HttpReq>(
            header,
            [this](std::shared_ptr<HttpRes> res){return response(nullptr, res);},
            [this]{ rwer->Unblock(0);});

    statuslist.emplace_back(ReqStatus{req, nullptr, nullptr, 0, nullptr});
    distribute(req, this);
    return req;
}

size_t Guest_sni::sniffer(Buffer&& bb) {
    char *hostname = nullptr;
    int ret = parse_tls_header((unsigned const char*)bb.data(), bb.len, &hostname);
    defer(free, hostname);
    if(ret == -1) {
        // not enough data, wait for more
        return 0;
    }
    LOGD(DHTTP, "[sni] forward to %s\n", hostname);
    auto req = forward(hostname, Protocol::TCP);
    if(req == nullptr){
        deleteLater(SNI_HOST_ERR);
        return bb.len;
    }
    auto len = bb.len;
    req->send(std::move(bb));
    rwer->SetReadCB([this](Buffer&& bb){return ReadHE(std::move(bb));});
    rx_bytes += len;
    return len;
}

size_t Guest_sni::sniffer_quic(Buffer&& bb) {
    auto len = bb.len;
    char *hostname = nullptr;
    defer(free, hostname);
#ifdef HAVE_QUIC
    quic_pkt_header header;
    int body_len = unpack_meta(bb.data(), len, &header);
    if (body_len < 0 || body_len > (int)len) {
        LOGE("QUIC sni meta unpack failed, body_len: %d, bufflen: %d\n", body_len, (int)len);
        goto Forward;
    }
    if(header.type != QUIC_PACKET_INITIAL) {
        LOGE("QUIC sni packet type is not initial: 0x%x\n", header.type);
        goto Forward;
    }
    quic_secret secret;
    if(quic_generate_initial_key(1, header.dcid.c_str(), header.dcid.size(), &secret) < 0){
        LOGE("Quic sni faild to generate initial key\n");
        goto Forward;
    }
    {
        auto buffer = std::make_unique<char[]>(body_len);
        size_t length = 0;
        size_t max_off = 0;
        auto frames = decode_packet(bb.data(), body_len, &header, &secret);
        for(const auto& frame: frames) {
            if(frame->type != QUIC_FRAME_CRYPTO){
                continue;
            }
            length += frame->crypto.length;
            memcpy(buffer.get() + frame->crypto.offset, frame->crypto.buffer->data(), frame->crypto.length);
            if(frame->crypto.offset + frame->crypto.length > max_off) {
                max_off = frame->crypto.offset + frame->crypto.length;
            }
            frame_release(frame);
        }
        if(max_off == 0 || max_off < length) {
            LOGE("Quic sni faild to get ClientHello: %zd vs %zd\n", max_off, length);
            goto Forward;
        }
        int ret = parse_client_hello((unsigned const char *)buffer.get(), length, &hostname);
        if (ret <= 0) {
            LOGE("Quic faild to parse sni from clientHello: %d\n", ret);
            goto Forward;
        }
    }
Forward:
    LOGD(DQUIC, "[sni] forward to %s\n", hostname);
#endif
    auto req = forward(hostname, Protocol::UDP);
    if(req == nullptr) {
        deleteLater(SNI_HOST_ERR);
        return bb.len;
    }
    req->send(std::move(bb));
    rwer->SetReadCB([this](Buffer&& bb){return ReadHE(std::move(bb));});
    rx_bytes += len;
    return len;
}
