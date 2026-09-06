#include "guest_sni.h"
#include "prot/tls.h"
#include "prot/sslio.h"
#include "prot/memio.h"
#include "misc/config.h"
#include "res/responser.h"

#ifdef HAVE_QUIC
#include "prot/quic/quicio.h"
#include "guest3.h"
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <string>
#include <arpa/inet.h>
#include <strings.h>

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
    this->df = std::move(df);
}

Guest_sni::Guest_sni(std::shared_ptr<RWer> rwer, std::shared_ptr<HttpReqHeader> req):
        Guest(rwer), req(std::move(req))
{
    assert(this->req);
    headless = true;
    if(std::dynamic_pointer_cast<PMemRWer>(rwer)) {
        cb->onRead([this](Buffer&& bb){return sniffer_quic(std::move(bb));});
    } else if(std::dynamic_pointer_cast<MemRWer>(rwer)) {
        cb->onRead([this](Buffer&& bb){return sniffer(std::move(bb));});
    } else {
        LOGF("Guest_sni: rwer type error\n");
    }
    Http_Proc = &Guest_sni::AlwaysProc;
}

static bool is_ip_host(const std::string& host) {
    in_addr a4;
    in6_addr a6;
    return inet_pton(AF_INET, host.c_str(), &a4) == 1 ||
           inet_pton(AF_INET6, host.c_str(), &a6) == 1;
}

bool should_sniff_sni(std::shared_ptr<const HttpReqHeader> req, Requester* src) {
    if(req->Dest.port != HTTPSPORT) {
        return false;
    }
    if(opt.mimic || !req->ismethod("CONNECT")) {
        return false;
    }
    bool tcp = strcmp(req->Dest.protocol, "tcp") == 0;
    bool udp = strcmp(req->Dest.protocol, "udp") == 0;
#ifndef HAVE_QUIC
    if(udp) {
        //无QUIC支持的构建解不出QUIC Initial，嗅探注定无产出
        return false;
    }
#endif
    if(!tcp && !udp) {
        return false;
    }
    if(is_ip_host(req->Dest.hostname) || strcmp(req->Dest.hostname, "fake_ip") == 0) {
        return true;
    }
    return shouldNegotiate(req, src);
}

Guest::ReqStatus* Guest_sni::forward(const char* sni, bool ech, Protocol prot, uint64_t id) {
    assert(statuslist.empty());
    assert(sni);
    if(req == nullptr && sni[0] == '\0') {
        LOGE("Guest_sni: no req and no sni to forward\n");
        return nullptr;
    }
    //known为权威已知域名(fakeip反查域名/CONNECT显式主机名)、IP串、空串
    //(listen路径)或哨兵"fake_ip"(重启后映射丢失)
    const std::string known = req ? req->Dest.hostname : "";
    std::string target = known;
    bool allow_mitm = true;
    if(!ech || known.empty() || known == "fake_ip") {
        //无ECH或无有效目标时信任SNI
        if (sni[0]) {
            target = sni;
        }
    }else if(strcasecmp(sni, known.c_str()) != 0) {
        //除非 sni和known一致(GREASE模式)，不然拿到的sni就不可靠，做不了mitm
        allow_mitm = false;
    }
    if(!allow_mitm) {
        LOG("[sni] ECH detected, sni:%s, known:%s, forward %s via tunnel\n",
            sni, known.c_str(), target.c_str());
    }
    if(req == nullptr)  {
        //listen路径：按嗅探结果合成CONNECT请求
        char buff[HEADLENLIMIT];
        int slen = snprintf(buff, sizeof(buff), "CONNECT %s:%d" CRLF, target.c_str(), 443);
        if(prot == Protocol::UDP) {
            slen += snprintf(buff + slen, sizeof(buff) - slen, "Protocol: udp" CRLF);
        }
        slen += snprintf(buff + slen, sizeof(buff) - slen, CRLF);
        req = UnpackHttpReq(buff, slen);
        req->set("User-Agent", generateUA(opt.ua, "", req->request_id));
        req->skip_authorize = true;
    }else if(target != known) {
        snprintf(req->Dest.hostname, sizeof(req->Dest.hostname), "%s", target.c_str());
    }
    assert(req->Dest.hostname[0]);
    assert(req->Dest.port == HTTPSPORT);
    req->set("User-Agent", generateUA(req->get("User-Agent"), "", req->request_id));
    bool do_mitm = allow_mitm && shouldNegotiate(req, this);
    auto cb = response(id);
    std::shared_ptr<MemRWer> rw;
    if(prot == Protocol::TCP) {
        if(do_mitm) {
            ctx = initssl(0, req->Dest.hostname);
            auto srwer = std::make_shared<SslMer>(ctx, getSrc(), getDst(), cb);
            srwer->set_server_name(req->Dest.hostname);
            rw = srwer;
            new Guest(srwer);
        } else {
            rw = std::make_shared<MemRWer>(getSrc(), getDst(), cb);
        }
    }
    if(prot == Protocol::UDP) {
#ifdef HAVE_QUIC
        if(do_mitm) {
            ctx = initssl(1, req->Dest.hostname);
            auto qrwer = std::make_shared<QuicMer>(ctx, getSrc(), getDst(), cb);
            rw = qrwer;
            new Guest3(qrwer);
        } else {
#else
        {
#endif
            rw = std::make_shared<PMemRWer>(getSrc(), getDst(), cb);
        }
    }
    //distribute可能同步回调错误响应(S407/S408/S504)，需要访问statuslist
    statuslist.emplace_back(ReqStatus{req, rw, cb, do_mitm ? HTTP_NOEND_F : 0u});
    if(!do_mitm) {
        distribute(req, rw);
    }
    return &statuslist.back();
}

Guest_sni::~Guest_sni() {
    if(ctx) SSL_CTX_free(ctx);
}

size_t Guest_sni::sniffer(Buffer&& bb) {
    if(bb.len == 0) {
        //嗅探期间对端关闭；deleteLater会Close掉rwer，经closeHE通知外层清理
        deleteLater(NOERROR);
        return 0;
    }
    struct sni_result result{};
    int ret = parse_tls_header((unsigned const char*)bb.data(), bb.len, &result);
    if(ret == -1) {
        // not enough data, wait for more
        return 0;
    }
    LOGD(DHTTP, "[sni] forward to %s\n", result.hostname);
    cb->onRead([this](Buffer&& bb){return ReadHE(std::move(bb));});
    auto status = forward(result.hostname, result.ech, Protocol::TCP, bb.id);
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
    const size_t len = bb.len;
    struct sni_result result{};

    if(bb.len == 0) {
        //嗅探期间对端关闭
        deleteLater(NOERROR);
        return 0;
    }
    auto buffer = std::make_unique<char[]>(BUF_LEN);
    size_t length = 0;
    size_t max_off = 0;
    int ret;
#ifdef HAVE_QUIC
    quic_init_packets.emplace_back(bb);
    for (const auto& ib: quic_init_packets) {
        quic_pkt_header header;
        //队列中的初始包会被后续嗅探重扫：decode_packet内mutable_data检测到共享
        //会自动COW拷贝再解密，原始密文不受影响，无需手动复制
        QuicCursor pkt((const unsigned char*)ib.data(), ib.len);
        auto meta = unpack_meta(pkt, 0);
        if (!meta) {
            LOGE("[%s] QUIC sni meta unpack failed, bufflen: %zd\n", dumpDest(rwer->getSrc()).c_str(), ib.len);
            goto Forward;
        }
        static_cast<quic_meta&>(header) = std::move(*meta);
        if(header.type != QUIC_PACKET_INITIAL) {
            LOGE("[%s] QUIC sni packet type is not initial: 0x%x\n", dumpDest(rwer->getSrc()).c_str(), header.type);
            goto Forward;
        }
        quic_secret secret;
        if(quic_generate_initial_key(1, header.dcid.c_str(), header.dcid.size(), &secret, header.version) < 0){
            LOGE("[%s] Quic sni faild to generate initial key\n", dumpDest(rwer->getSrc()).c_str());
            goto Forward;
        }
        std::deque<quic_frame> frames;
        if(decode_packet(Buffer(ib), &header, &secret, &frames) != quic_decode_status::ok){
            LOGE("[%s] Quic sni decode packet failed\n", dumpDest(rwer->getSrc()).c_str());
            goto Forward;
        }
        for(const auto& frame: frames) {
            if(frame.type != QUIC_FRAME_CRYPTO){
                continue;
            }
            LOGD(DQUIC, "sni get crypto %zd - %zd\n", (size_t)frame.crypto.offset,
                (size_t)frame.crypto.offset + (size_t)frame.crypto.length);
            if(frame.crypto.length + frame.crypto.offset > (size_t)BUF_LEN) {
                LOGE("[%s] Quic sni get crypto overflow bufflen: %zd\n", dumpDest(rwer->getSrc()).c_str(),
                    (size_t)frame.crypto.length + (size_t)frame.crypto.offset);
                goto Forward;
            }
            length += frame.crypto.length;
            memcpy(buffer.get() + frame.crypto.offset, frame.crypto.buffer->data(), frame.crypto.length);
            if(frame.crypto.offset + frame.crypto.length > max_off) {
                max_off = frame.crypto.offset + frame.crypto.length;
            }
        }
    }
    if(max_off == 0 || length < max_off) {
        return 0;
    }
    ret = parse_client_hello((unsigned const char*)buffer.get(), length, &result);
    if (ret == -1) {
        return 0;
    }
    if (ret <= 0) {
        LOGE("[%s] Quic faild to parse sni from clientHello: %d\n", dumpDest(rwer->getSrc()).c_str(), ret);
        goto Forward;
    }
Forward:
    LOGD(DQUIC, "[sni] forward to %s\n", result.hostname);
#else
    (void)length;
    (void)max_off;
    (void)ret;
#endif
    cb->onRead([this](Buffer&& bb){return ReadHE(std::move(bb));});
    auto status = forward(result.hostname, result.ech, Protocol::UDP, bb.id);
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
