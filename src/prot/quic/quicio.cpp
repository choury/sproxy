//
// Created by 周威 on 2021/6/20.
//
#include "quicio.h"
#include "quic_pack.h"
#include "misc/config.h"
#include "misc/util.h"
#include "prot/tls.h"
#include <openssl/err.h>
#include <unistd.h>
#include <assert.h>

#define QUIC_CIPHERS                                              \
   "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"               \
   "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"

#define QUIC_GROUPS "P-256:X25519:P-384:P-521"


static uint8_t getPacketType(OSSL_ENCRYPTION_LEVEL level) {
    switch(level){
    case ssl_encryption_initial:
        return QUIC_PACKET_INITIAL;
    case ssl_encryption_early_data:
        return QUIC_PACKET_0RTT;
    case ssl_encryption_handshake:
        return QUIC_PACKET_HANDSHAKE;
    case ssl_encryption_application:
        return QUIC_PACKET_1RTT;
    default:
        abort();
    }
}

static OSSL_ENCRYPTION_LEVEL getLevel(uint8_t type){
    switch(type){
    case QUIC_PACKET_INITIAL:
        return ssl_encryption_initial;
    case QUIC_PACKET_HANDSHAKE:
        return ssl_encryption_handshake;
    case QUIC_PACKET_0RTT:
        return ssl_encryption_early_data;
    case QUIC_PACKET_1RTT:
        return ssl_encryption_application;
    default:
        abort();
    }
}

void QuicRWer::dropkey(OSSL_ENCRYPTION_LEVEL level) {
    if(!sctx[level].valid){
        return;
    }
    sctx[level].valid = false;
    memset(&sctx[level].read_secret, 0, sizeof(quic_secret));
    memset(&sctx[level].write_secret, 0, sizeof(quic_secret));
}

int QuicRWer::set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) {
    LOGD(DQUIC, "set_secret: level %d, len: %zd\n", level, secret_len );
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    assert(secret_len <= 32);
    assert(level >= rwer->level_max);
    rwer->level_max = level;
    quic_secret_set_key(&rwer->sctx[level].read_secret, (const char*)read_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    quic_secret_set_key(&rwer->sctx[level].write_secret, (const char*)write_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    rwer->sctx[level].valid = true;
    //drop init key
    rwer->dropkey(ssl_encryption_initial);
    return 1;
}

int QuicRWer::sendNsPacket(OSSL_ENCRYPTION_LEVEL level, pn_namespace* pnNs){
    if(pnNs->pn_acked >= pnNs->pn_seen && pnNs->pendq.empty()){
        return 0;
    }

    char buff[1500];
    size_t pos = 0;
    if(pnNs->pn_acked < pnNs->pn_seen){
        quic_frame ack;
        memset(&ack, 0, sizeof(quic_frame));
        ack.type = QUIC_FRAME_ACK;
        ack.ack.acknowledged = pnNs->pn_seen;
        ack.ack.delay = getmtime() - pnNs->seen_time;
        LOGD(DQUIC, "< ack frame [%llu/%d]: %llu [%llu]\n",
             pnNs->pn_current, level, ack.ack.acknowledged, ack.ack.delay);
        pnNs->pn_acked = pnNs->pn_seen;
        int ret = pack_frame(buff + pos, &ack);
        if(ret < 0){
            ErrorHE(PROTOCOL_ERR, 0);
            return -1;
        }
        pos += ret;
    }

    pnNs->pn_current++;
    for(auto frame: pnNs->pendq) {
        assert(frame->type != QUIC_FRAME_PADDING);
        int ret = pack_frame(buff + pos, frame);
        if(ret < 0){
            ErrorHE(PROTOCOL_ERR, 0);
            return -1;
        }
        pos += ret;
        pnNs->sendq.push_back(quic_frame_pn{pnNs->pn_current, frame});
    }
    quic_pkt_header header;
    memset(&header, 0, sizeof(header));
    header.meta.type = getPacketType(level);
    header.meta.dcid = dcid;
    header.meta.scid = scid;
    header.meta.version = QUIC_VERSION_1;

    header.pn = pnNs->pn_current;
    header.pn_length = 4;
    header.pn_acked = pnNs->pn_acked;
    const quic_secret* secret = &sctx[level].write_secret;

    char packet[1500];
    int packet_len = encode_packet(buff, pos, &header, secret, packet);
    if(packet_len < 0){
        LOGE("QUIC failed to pack packet");
        ErrorHE(PROTOCOL_ERR, 0);
        return -1;
    }
    if(header.meta.type == QUIC_PACKET_INITIAL && packet_len < 1200){
        packet_len = 1200;
    }
    
    int ret = write(getFd(), packet, packet_len);
    if(ret < 0 && errno != EAGAIN){
        ErrorHE(SOCKET_ERR, errno);
        return -1;
    }
    pnNs->pendq.clear();
    return 0;
}

void QuicRWer::sendPacket(){
    for(int i = 0; i < 4; i ++){
        if(!sctx[i].valid){
            continue;
        }
        if(sendNsPacket((OSSL_ENCRYPTION_LEVEL)i, sctx[i].pnNs) < 0){
            return;
        }
    }
}

int QuicRWer::add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len) {
    LOGD(DQUIC, "add_handshake_data: level %d, len: %zd\n", level, len);
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);

    auto& sctx = rwer->sctx[level];

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CRYPTO;
    frame->crypto.body = new char[len];
    memcpy(frame->crypto.body, data, len);
    frame->crypto.offset = sctx.crypto_offset;
    frame->crypto.length = len;
    LOGD(DQUIC, "< [%d] crypto frame: %lu - %lu\n", level,
         frame->crypto.offset, frame->crypto.offset+frame->crypto.length);

    rwer->PushFrame(sctx.pnNs, frame);
    sctx.crypto_offset += len;
    return 1;
}

int QuicRWer::flush_flight(SSL *ssl){
    return 1;
}

int QuicRWer::send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert){
    LOGD(DQUIC, "send_alert: level: %d, alert: %d\n", level, alert);
    return 1;
}

static SSL_QUIC_METHOD quic_method{
    QuicRWer::set_encryption_secrets,
    QuicRWer::add_handshake_data,
    QuicRWer::flush_flight,
    QuicRWer::send_alert,
};

void QuicRWer::generatecid() {
    dcid.resize(20);
    scid.resize(20);
    snprintf(&scid[0], sizeof(scid), "sproxy0000%d", rand());
    snprintf(&dcid[0], sizeof(dcid), "sproxy0000%d", rand());
    set32(&dcid[6], getutime());
    set32(&scid[6], getutime());
    quic_generate_initial_key(1, dcid.data(), dcid.length(), &sctx[0].write_secret);
    quic_generate_initial_key(0, dcid.data(), dcid.length(), &sctx[0].read_secret);
    sctx[0].valid = true;
    sctx[0].pnNs = new pn_namespace;
    sctx[2].pnNs = new pn_namespace;
    sctx[1].pnNs = sctx[3].pnNs = new pn_namespace;
}

QuicRWer::QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                   std::function<void(int, int)> errorCB,
                   std::function<void(const sockaddr_storage&)> connectCB):
        SocketRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB))
{
    assert(protocol == Protocol::QUIC);
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        LOGE("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_write_line);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if(SSL_CTX_set_ciphersuites(ctx, QUIC_CIPHERS) != 1) {
        LOGE("SSL_CTX_set_ciphersuites: %s", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }

    if(SSL_CTX_set1_groups_list(ctx, QUIC_GROUPS) != 1) {
        LOGE("SSL_CTX_set1_groups_list failed");
        throw 0;
    }

    SSL_CTX_set_quic_method(ctx, &quic_method);
#if __ANDROID__
    if (SSL_CTX_load_verify_locations(ctx, opt.cafile, "/etc/security/cacerts/") != 1)
#else
    if (SSL_CTX_load_verify_locations(ctx, opt.cafile, "/etc/ssl/certs/") != 1)
#endif
        LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    ssl = SSL_new(ctx);
    if(ssl == nullptr){
        LOGE("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }
    SSL_set_app_data(ssl, this);
    generatecid();
    char quic_params[1200];
    int p = variable_encode(quic_params, quic_initial_source_connection_id);
    p += variable_encode(quic_params + p, scid.length());
    memcpy(quic_params + p, scid.data(), scid.length());
    p += scid.length();
    p += variable_encode(quic_params + p, quic_max_udp_payload_size);
    p += variable_encode(quic_params + p, variable_encode_len(1280));
    p += variable_encode(quic_params + p, 1280);
    p += variable_encode(quic_params + p, quic_initial_max_streams_bidi);
    p += variable_encode(quic_params + p, 1);
    p += variable_encode(quic_params + p, 100);
    p += variable_encode(quic_params + p, quic_initial_max_streams_uni);
    p += variable_encode(quic_params + p, 1);
    p += variable_encode(quic_params + p, 100);
    SSL_set_quic_transport_params(ssl, (const uint8_t*)quic_params, p);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);
}

QuicRWer::~QuicRWer(){
    if(!SSL_in_init(ssl)){
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
    deljob(&packet_tx);
    delete sctx[0].pnNs;
    delete sctx[1].pnNs;
    delete sctx[2].pnNs;
}

void QuicRWer::PushFrame(pn_namespace* pnNs, quic_frame* frame) {
    pnNs->pendq.push_back(frame);
    updatejob(packet_tx, std::bind(&QuicRWer::sendPacket, this) , 0);
}

void QuicRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        checkSocket(__PRETTY_FUNCTION__);
        return connect();
    }
    if (!!(events & RW_EVENT::WRITE)) {
        stats = RWerStats::SslConnecting;

        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname));

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);

        ssl_get_error(ssl, SSL_do_handshake(ssl));
        if (errno != EAGAIN) {
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
            ErrorHE(SSL_SHAKEHAND_ERR, error);
            return;
        }
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&QuicRWer::defaultHE;
        con_failed_job = updatejob(con_failed_job, std::bind(&QuicRWer::connect, this), 1000);
    }
}

PacketResult QuicRWer::handlePacketBeforeHandshake(const quic_packet *packet) {
    auto& header = packet->header;
    if(header.meta.type == QUIC_PACKET_INITIAL){
        dcid = header.meta.scid;
    }
    auto level = getLevel(header.meta.type);
    auto& pnNs = sctx[level].pnNs;
    if(header.pn >= pnNs->pn_seen){
        pnNs->pn_seen = header.pn;
        pnNs->seen_time = getmtime();
    }
    for(auto frame: packet->frames){
        //CRYPTO, ACK frames, or both. PING, PADDING, and CONNECTION_CLOSE frames
        switch(frame->type){
        case QUIC_FRAME_PADDING:
            break;
        case QUIC_FRAME_PING:
            LOGD(DQUIC, "> [%d] ping frame [%lu]\n", level, header.pn);
            break;
        case QUIC_FRAME_ACK:
            LOGD(DQUIC, "> [%d] ack frame [%lu]: %lu[%lu]\n", level,
                 header.pn, frame->ack.acknowledged, frame->ack.delay);
            break;
        case QUIC_FRAME_CONNECTION_CLOSE:
            LOGD(DQUIC, "> [%d] close frame [%lu]: %d\n", level, header.pn, frame->close.error);
            LOGE("peer closed connection: %d\n", frame->close.error);
            ErrorHE(SSL_SHAKEHAND_ERR, frame->close.error);
            return PacketResult::error;
        case QUIC_FRAME_CRYPTO:
            LOGD(DQUIC, "> [%d] crypto frame [%lu]: %lu - %lu\n", level,
                 header.pn, frame->crypto.offset, frame->crypto.offset+frame->crypto.length);
            if(frame->crypto.offset != sctx[level].crypto_want){
                LOGD(DQUIC, "ignore unwant crypto frame [%zd]\n", sctx[level].crypto_want);
                break;
            }
            sctx[level].crypto_want += frame->crypto.length;
            SSL_provide_quic_data(ssl, level, (uint8_t *)frame->crypto.body, frame->crypto.length);
            if(ssl_get_error(ssl, SSL_do_handshake(ssl)) == 1){
                LOGD(DQUIC, "SSL_do_handshake succeed\n");
                break;
            }
            if(errno != EAGAIN){
                int error = errno;
                LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
                ErrorHE(SSL_SHAKEHAND_ERR, error);
                return PacketResult::error;
            }
            break;
        default:
            LOGE("[%d] unexpected frame: 0x%x\n", level, frame->type);
            ErrorHE(SSL_SHAKEHAND_ERR, EPROTO);
            return PacketResult::error;
        }
    }
    return PacketResult::ok;
}

PacketResult QuicRWer::handlePacket(const quic_packet *packet) {
    if(packet->header.meta.dcid != scid){
        LOG("QUIC unknow dcid\n");
        return PacketResult::ok;
    }
    const quic_pkt_header* header = &packet->header;
    if(header->meta.type != QUIC_PACKET_1RTT){
        return handlePacketBeforeHandshake(packet);
    }
    if(sctx[ssl_encryption_handshake].valid){
        //drop handshake key
        dropkey(ssl_encryption_handshake);
    }
    auto pnNs = sctx[ssl_encryption_application].pnNs;
    if(header->pn >= pnNs->pn_seen){
        pnNs->pn_seen = header->pn;
        pnNs->seen_time = getmtime();
    }
    updatejob(packet_tx, std::bind(&QuicRWer::sendPacket, this) , 25);
    for(auto frame : packet->frames) {
        switch (frame->type) {
        case QUIC_FRAME_PADDING:
            break;
        case QUIC_FRAME_CRYPTO:
            LOGD(DQUIC, "> [a] crypto frame [%lu]: %lu - %lu\n",
                 header->pn, frame->crypto.offset, frame->crypto.offset+frame->crypto.length);
            if(frame->crypto.offset != sctx[ssl_encryption_application].crypto_want){
                LOGD(DQUIC, "ignore unwant crypto frame [%zd]\n", sctx[ssl_encryption_application].crypto_want);
                break;
            }
            sctx[ssl_encryption_application].crypto_want += frame->crypto.length;
            SSL_provide_quic_data(ssl, ssl_encryption_application, (uint8_t *)frame->crypto.body, frame->crypto.length);
            if(ssl_get_error(ssl, SSL_process_quic_post_handshake(ssl)) != 1){
                int error = errno;
                LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
                ErrorHE(PROTOCOL_ERR, error);
                return PacketResult::error;
            }
            break;
        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
            LOGD(DQUIC, "> [a] ack frame [%lu]: %lu[%lu]\n",
                 header->pn, frame->ack.acknowledged, frame->ack.delay);
            break;
        case QUIC_FRAME_PING:
            LOGD(DQUIC, "> [a] ping frame [%lu]\n", header->pn);
            break;
        case QUIC_FRAME_HANDSHAKE_DONE:
            LOGD(DQUIC, "> [a] handshake_done frame [%lu]\n", header->pn);
            if(stats == RWerStats::SslConnecting){
                LOGD(DQUIC, "ssl handshake completed\n");
                Connected(addrs.front());
            }
            break;
        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
            LOGD(DQUIC, "> [a] close from [%lu] code: %lu, reason: %.*s\n",
                 header->pn, frame->close.error,
                 (int)frame->close.reason_len, frame->close.reason);
            ErrorHE(PROTOCOL_ERR, frame->close.error);
            break;
        default:
            LOGD(DQUIC, "> [a] ignore frame [%lu]: 0x%lx\n", header->pn, frame->type);
            break;
        }
    }
    return PacketResult::ok;
}

ssize_t QuicRWer::Write(const void *buff, size_t len) {
    LOG("quic write: %zd\n", len);
    if(streammap.count(stream_current) == 0){
        streammap[stream_current] = QuicStreamStat{};
    }
    auto& streamstat = streammap[stream_current];
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_STREAM_START | QUIC_FRAME_STREAM_OFF_F | QUIC_FRAME_STREAM_LEN_F;
    if(len == 0){
        frame->type |= QUIC_FRAME_STREAM_FIN_F;
    }
    frame->stream.type = frame->type;
    frame->stream.id = stream_current;
    frame->stream.length = len;
    frame->stream.offset =  streamstat.offset;
    streamstat.offset += len;
    frame->stream.data = new char[len];
    memcpy(frame->stream.data, buff, len);
    PushFrame(sctx[ssl_encryption_application].pnNs, frame);
    return len;
}

void QuicRWer::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int QuicRWer::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

void QuicRWer::ReadData() {
    char buff[1500];
    int ret = read(getFd(), buff, sizeof(buff));
    if(ret < 0){
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    LOGD(DQUIC, "read bytes from socket: %d\n", ret);
    int pos = 0;
    while(pos < ret) {
        if(buff[pos] == 0){
            pos++;
            continue;
        }
        quic_pkt_header header;
        int body_len = unpack_meta(buff + pos, ret - pos, &header.meta);
        if(body_len < 0){
            LOGE("QUIC meta unpack failed\n");
            ErrorHE(PROTOCOL_ERR, EPROTO);
            return;
        }
        OSSL_ENCRYPTION_LEVEL level = getLevel(header.meta.type);
        if(!sctx[level].valid){
            LOG("quic key for %d is invalid, drop it (%d).\n", level, body_len);
            pos += body_len;
            continue;
        }

        header.pn_acked = sctx[level].pnNs->pn_acked;
        header.meta.dcid = scid;
        const quic_secret* secret = &sctx[level].read_secret;
        auto frames = decode_frame(buff + pos, body_len, &header, secret);
        if (frames.empty()) {
            LOGE("QUIC packet unpack failed\n");
            ErrorHE(PROTOCOL_ERR, EPROTO);
            return;
        }
        pos += body_len;

        quic_packet* packet = new quic_packet{header, frames};
        switch(handlePacket(packet)){
        case PacketResult::ok:
            delete packet;
            continue;
        case PacketResult::skip:
            break;
        case PacketResult::error:
            delete packet;
            return;
        }
        LOGD(DQUIC, "push packet [%llu/%d] to queue\n", packet->header.pn, level);
        recvq.push_back(packet);
    }
    for(auto i = recvq.begin(); i != recvq.end();) {
        auto packet = *i;
        switch(handlePacket(packet)){
        case PacketResult::ok:
            delete *i;
            i = recvq.erase(i);
            break;
        case PacketResult::skip:
            i++;
            break;
        case PacketResult::error:
            return;
        }
    }
}

const char * QuicRWer::rdata() {
    return nullptr;
}

size_t QuicRWer::rleft() {
    return 0;
}

size_t QuicRWer::rlength() {
    return 0;
}

void QuicRWer::consume(const char *data, size_t l) {
}
