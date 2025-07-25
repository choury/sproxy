#include "guest_sni.h"
#include "prot/tls.h"
#include "prot/sslio.h"
#include "misc/config.h"
#include "misc/defer.h"
#include "res/responser.h"

#ifdef HAVE_QUIC
#include "prot/quic/quicio.h"
#include "guest3.h"
#endif

#include <stdlib.h>
#include <inttypes.h>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx, std::function<void(Server*)> df):Guest(fd, addr, ctx){
    assert(ctx == nullptr);
    headless = true;
    int type;
    socklen_t len = sizeof(type);
    if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) < 0){
        LOGF("Faild to get socket type: %s\n", strerror(errno));
    }
    if(type == SOCK_STREAM) {
        cb->onRead([this](Buffer&& bb){return sniffer(std::move(bb));});
    }else if (type == SOCK_DGRAM) {
        cb->onRead([this](Buffer&& bb){return sniffer_quic(std::move(bb));});
    }else {
        LOGF("unknown socket type: %d\n", type);
    }

    Http_Proc = &Guest_sni::AlwaysProc;
    user_agent = generateUA(opt.ua, "", 0);
    this->df = std::move(df);
}

Guest_sni::Guest_sni(std::shared_ptr<RWer> rwer, std::string host, const char* ua):
        Guest(rwer), host(std::move(host))
{
    headless = true;
    if(ua) {
        user_agent = ua;
    }
    if(std::dynamic_pointer_cast<PMemRWer>(rwer)) {
        cb->onRead([this](Buffer&& bb){return sniffer_quic(std::move(bb));});
    } else if(std::dynamic_pointer_cast<MemRWer>(rwer)) {
        cb->onRead([this](Buffer&& bb){return sniffer(std::move(bb));});
    } else {
        LOGF("Guest_sni: rwer type error\n");
    }
    Http_Proc = &Guest_sni::AlwaysProc;
}

Guest::ReqStatus* Guest_sni::forward(const char *hostname, Protocol prot, uint64_t id) {
    if (hostname && hostname[0]){
        host = hostname;
    }
    hostname = host.c_str();
    if(*hostname == '\0') {
        LOGE("Guest_sni: empty hostname\n");
        return nullptr;
    }
    assert(statuslist.empty());
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
    std::shared_ptr<HttpReqHeader> req = UnpackHttpReq(buff, slen);
    if(req == nullptr) {
        LOGE("Guest_sni: UnpackHttpReq failed\n");
        return nullptr;
    }
    req->set("User-Agent", generateUA(user_agent.c_str(), "", req->request_id));

    auto _cb = response(id);
#ifdef HAVE_QUIC
    if(shouldNegotiate(hostname)) {
        if(prot == Protocol::TCP) {
#else
    if(shouldNegotiate(hostname) && prot == Protocol::TCP) {
#endif
            ctx = initssl(0, hostname);
            auto srwer = std::make_shared<SslMer>(ctx, rwer->getSrc(), _cb);
            statuslist.emplace_back(ReqStatus{req, srwer, _cb, HTTP_NOEND_F});
            new Guest(srwer);
#ifdef HAVE_QUIC
        } else {
            ctx = initssl(1, hostname);
            auto srwer = std::make_shared<QuicMer>(ctx, rwer->getSrc(), _cb);
            statuslist.emplace_back(ReqStatus{req, srwer, _cb, HTTP_NOEND_F});
            new Guest3(srwer);
        }
#endif
    } else {
        headless = true;
        ReqProc(req->request_id, req);
    }
    return &statuslist.back();
}

Guest_sni::~Guest_sni() {
    if(ctx) SSL_CTX_free(ctx);
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
    cb->onRead([this](Buffer&& bb){return ReadHE(std::move(bb));});
    auto status = forward(hostname, Protocol::TCP, bb.id);
    if(status == nullptr){
        deleteLater(SNI_HOST_ERR);
        return bb.len;
    }
    auto len = bb.len;
    status->rw->push_data(std::move(bb));
    rx_bytes += len;
    return len;
}

size_t Guest_sni::sniffer_quic(Buffer&& bb) {
    auto len = bb.len;
    char* hostname = nullptr;
    defer([](char** ptr){free(*ptr);}, &hostname);

    auto buffer = std::make_unique<char[]>(BUF_LEN);
    size_t length = 0;
    size_t max_off = 0;
    int ret;
#ifdef HAVE_QUIC
    quic_init_packets.emplace_back(bb);
    for (const auto& bb: quic_init_packets) {
        quic_pkt_header header;
        int body_len = unpack_meta(bb.data(), len, &header);
        if (body_len < 0 || body_len > (int)len) {
            LOGE("[%s] QUIC sni meta unpack failed, body_len: %d, bufflen: %d\n", dumpDest(rwer->getSrc()).c_str(), body_len, (int)len);
            goto Forward;
        }
        if(header.type != QUIC_PACKET_INITIAL) {
            LOGE("[%s] QUIC sni packet type is not initial: 0x%x\n", dumpDest(rwer->getSrc()).c_str(), header.type);
            goto Forward;
        }
        quic_secret secret;
        if(quic_generate_initial_key(1, header.dcid.c_str(), header.dcid.size(), &secret, header.version) < 0){
            LOGE("[%s] Quic sni faild to generate initial key\n", dumpDest(rwer->getSrc()).c_str());
            goto Forward;
        }
        auto frames = decode_packet(bb.data(), body_len, &header, &secret);
        for(const auto& frame: frames) {
            defer(frame_release, frame);
            if(frame->type != QUIC_FRAME_CRYPTO){
                continue;
            }
            LOGD(DQUIC, "sni get crypto %zd - %zd\n", (size_t)frame->crypto.offset,
                (size_t)frame->crypto.offset + (size_t)frame->crypto.length);
            if(frame->crypto.length + frame->crypto.offset > (size_t)BUF_LEN) {
                LOGE("[%s] Quic sni get crypto overflow bufflen: %zd\n", dumpDest(rwer->getSrc()).c_str(),
                    (size_t)frame->crypto.length + (size_t)frame->crypto.offset);
                goto Forward;
            }
            length += frame->crypto.length;
            memcpy(buffer.get() + frame->crypto.offset, frame->crypto.buffer->data(), frame->crypto.length);
            if(frame->crypto.offset + frame->crypto.length > max_off) {
                max_off = frame->crypto.offset + frame->crypto.length;
            }
        }
    }
    if(max_off == 0 || length < max_off) {
        return 0;
    }
    ret = parse_client_hello((unsigned const char*)buffer.get(), length, &hostname);
    if (ret == -1) {
        return 0;
    }
    if (ret <= 0) {
        LOGE("[%s] Quic faild to parse sni from clientHello: %d\n", dumpDest(rwer->getSrc()).c_str(), ret);
        goto Forward;
    }
Forward:
    LOGD(DQUIC, "[sni] forward to %s\n", hostname);
#else
    (void)length;
    (void)max_off;
    (void)ret;
#endif
    cb->onRead([this](Buffer&& bb){return ReadHE(std::move(bb));});
    auto status = forward(hostname, Protocol::UDP, bb.id);
    if(status == nullptr) {
        deleteLater(SNI_HOST_ERR);
        return bb.len;
    }
#ifdef HAVE_QUIC
    for (auto& bb: quic_init_packets) {
#endif
        rx_bytes += bb.len;
        status->rw->push_data(std::move(bb));
#ifdef HAVE_QUIC
    }
    quic_init_packets.clear();
#endif
    return len;
}
