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
#include <inttypes.h>


/*TODO:
 * 上层应用是否应该感知到QUIC层的流量控制？
 * 丢包重传
 * reset_stream包处理
 * 分包
 * 多地址，失败轮询重试
 * server端实现
 * 连接迁移
 */

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
    if(!context[level].valid){
        return;
    }
    context[level].valid = false;
    memset(&context[level].read_secret, 0, sizeof(quic_secret));
    memset(&context[level].write_secret, 0, sizeof(quic_secret));
}

int QuicRWer::set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) {
    LOGD(DQUIC, "set_secret: level %d, len: %zd\n", level, secret_len );
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    assert(secret_len <= 32);
    quic_secret_set_key(&rwer->context[level].read_secret, (const char*)read_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    quic_secret_set_key(&rwer->context[level].write_secret, (const char*)write_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    rwer->context[level].valid = true;
    //drop init key
    rwer->dropkey(ssl_encryption_initial);
    return 1;
}

int QuicRWer::sendNsPacket(OSSL_ENCRYPTION_LEVEL level, pn_namespace* pnNs){
    char buff[1500];
    char* pos = buff;
    pnNs->PendAck();
    for(auto frame: pnNs->pendq) {
        pos = (char*)pack_frame(pos, frame);
        if(pos == nullptr){
            ErrorHE(PROTOCOL_ERR, 0);
            return -1;
        }
        pnNs->sendq.push_back(quic_frame_pn{pnNs->current, frame});
    }
    if(pos == buff){
        //there is no frame
        return 0;
    }
    quic_pkt_header header;
    header.meta.type = getPacketType(level);
    header.meta.dcid = dcids[dcid_id].id;
    header.meta.scid = scids[scid_id].id;
    header.meta.version = QUIC_VERSION_1;
    header.meta.token = initToken;

    header.pn = pnNs->current;
    header.pn_length = 4;
    header.pn_acked = pnNs->largest_ack;
    const quic_secret* secret = &context[level].write_secret;

    char packet[1500];
    pos = encode_packet(buff, pos - buff, &header, secret, packet);
    if(pos == nullptr){
        LOGE("QUIC failed to pack packet");
        ErrorHE(PROTOCOL_ERR, 0);
        return -1;
    }
    size_t packet_len = pos - packet;
    if(header.meta.type == QUIC_PACKET_INITIAL && packet_len < QUIC_INITIAL_LIMIT){
        memset(pos, 0, packet + sizeof(packet) - pos);
        packet_len = QUIC_INITIAL_LIMIT;
    }
    
    ssize_t ret = write(getFd(), packet, packet_len);
    if(ret < 0 && errno != EAGAIN){
        ErrorHE(SOCKET_ERR, errno);
        return -1;
    }
    pnNs->pendq.clear();
    pnNs->current++;
    return 0;
}

void QuicRWer::sendPacket(){
    for(int i = 0; i < 4; i ++){
        if(!context[i].valid){
            continue;
        }
        if(sendNsPacket((OSSL_ENCRYPTION_LEVEL)i, context[i].pnNs) < 0){
            return;
        }
    }
    keep_alive = updatejob(keep_alive, std::bind(&QuicRWer::keepAlive, this), 30000);
}

int QuicRWer::add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len) {
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    auto& sctx = rwer->context[level];

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CRYPTO;
    frame->crypto.body = new char[len];
    memcpy(frame->crypto.body, data, len);
    frame->crypto.offset = sctx.crypto_offset;
    frame->crypto.length = len;
    LOGD(DQUIC, "< [%c] crypto frame: %" PRIu64" - %" PRIu64"\n", sctx.pnNs->name,
         frame->crypto.offset, frame->crypto.offset+frame->crypto.length);

    rwer->PushFrame(sctx.pnNs, frame);
    sctx.crypto_offset += len;
    return 1;
}

int QuicRWer::flush_flight(SSL *){
    return 1;
}

int QuicRWer::send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert){
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    if(rwer->stats == RWerStats::Error){
        return 1;
    }
    auto& sctx = rwer->context[level];
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CONNECTION_CLOSE;
    frame->close.error = 0x100 + alert;
    frame->close.frame_type = QUIC_FRAME_CRYPTO;
    frame->close.reason_len = 0;
    frame->close.reason = nullptr;

    LOGD(DQUIC, "[%d] ssl send_alert: %d\n", level, alert);
    rwer->PushFrame(sctx.pnNs, frame);
    return 1;
}

static SSL_QUIC_METHOD quic_method{
    QuicRWer::set_encryption_secrets,
    QuicRWer::add_handshake_data,
    QuicRWer::flush_flight,
    QuicRWer::send_alert,
};

void QuicRWer::generateCid() {
    cid dcid, scid;
    dcid.id.resize(QUIC_CID_LEN);
    scid.id.resize(QUIC_CID_LEN);
    snprintf(&scid.id[0], sizeof(scids), "sproxy0000%d", rand());
    snprintf(&dcid.id[0], sizeof(dcids), "sproxy0000%d", rand());
    set32(&dcid.id[6], getutime());
    set32(&scid.id[6], getutime());
    quic_generate_initial_key(1, dcid.id.data(), dcid.id.length(), &context[0].write_secret);
    quic_generate_initial_key(0, dcid.id.data(), dcid.id.length(), &context[0].read_secret);

    scids.push_back(scid);
    dcids.push_back(dcid);

    context[0].valid = true;
    context[0].pnNs = new pn_namespace;
    context[0].pnNs->name = 'i';

    context[2].pnNs = new pn_namespace;
    context[2].pnNs->name = 'h';

    context[1].pnNs = context[3].pnNs = new pn_namespace;
    context[1].pnNs->name = 'a';
}

size_t QuicRWer::generateParams(char data[QUIC_INITIAL_LIMIT]) {
    char* pos = data;
    pos += variable_encode(pos, quic_initial_source_connection_id);
    pos += variable_encode(pos, scids[0].id.length());
    memcpy(pos, scids[0].id.data(), scids[0].id.length());
    pos += scids[0].id.length();
    pos += variable_encode(pos, quic_max_idle_timeout);
    pos += variable_encode(pos, variable_encode_len(max_idle_timeout));
    pos += variable_encode(pos, max_idle_timeout);
    pos += variable_encode(pos, quic_max_udp_payload_size);
    pos += variable_encode(pos, variable_encode_len(my_max_payload_size));
    pos += variable_encode(pos, my_max_payload_size);
    pos += variable_encode(pos, quic_initial_max_streams_bidi);
    pos += variable_encode(pos, variable_encode_len(my_max_streams_bidi));
    pos += variable_encode(pos, my_max_streams_bidi);
    pos += variable_encode(pos, quic_initial_max_streams_uni);
    pos += variable_encode(pos, variable_encode_len(my_max_streams_uni));
    pos += variable_encode(pos, my_max_streams_uni);
    pos += variable_encode(pos, quic_initial_max_data);
    pos += variable_encode(pos, variable_encode_len(my_max_data));
    pos += variable_encode(pos, my_max_data);
    pos += variable_encode(pos, quic_initial_max_stream_data_bidi_local);
    pos += variable_encode(pos, variable_encode_len(my_max_stream_data_bidi_local));
    pos += variable_encode(pos, my_max_stream_data_bidi_local);
    pos += variable_encode(pos, quic_initial_max_stream_data_bidi_remote);
    pos += variable_encode(pos, variable_encode_len(my_max_stream_data_bidi_remote));
    pos += variable_encode(pos, my_max_stream_data_bidi_remote);
    pos += variable_encode(pos, quic_initial_max_stream_data_uni);
    pos += variable_encode(pos, variable_encode_len(my_max_stream_data_uni));
    pos += variable_encode(pos, my_max_stream_data_uni);
    return pos - data;
}

QuicRWer::QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                   std::function<void(int, int)> errorCB,
                   std::function<void(const sockaddr_storage&)> connectCB):
        SocketRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB))
{
    assert(protocol == Protocol::QUIC);
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        LOGF("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_write_line);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if(SSL_CTX_set_ciphersuites(ctx, QUIC_CIPHERS) != 1) {
        LOGF("SSL_CTX_set_ciphersuites: %s", ERR_error_string(ERR_get_error(), nullptr));
    }

    if(SSL_CTX_set1_groups_list(ctx, QUIC_GROUPS) != 1) {
        LOGF("SSL_CTX_set1_groups_list failed");
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
        LOGF("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_set_app_data(ssl, this);
    generateCid();
    char quic_params[QUIC_INITIAL_LIMIT];
    SSL_set_quic_transport_params(ssl, (const uint8_t*)quic_params, generateParams(quic_params));
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);
    nextLocalBiId   = 0;
    nextRemoteBiId  = 1;
    nextLocalUbiId  = 2;
    nextRemoteUbiId = 3;
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
    deljob(&keep_alive);
    delete context[0].pnNs;
    delete context[1].pnNs;
    delete context[2].pnNs;
}

void QuicRWer::PushFrame(pn_namespace* pnNs, quic_frame* frame) {
    assert(frame->type != QUIC_FRAME_ACK && frame->type != QUIC_FRAME_ACK_ECN);
    pnNs->pendq.push_back(frame);
    packet_tx = updatejob(packet_tx, std::bind(&QuicRWer::sendPacket, this) , 0);
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
        con_failed_job = updatejob(con_failed_job, std::bind(&QuicRWer::connect, this), 2000);
    }
}

PacketResult QuicRWer::handleCryptoPacket(const quic_crypto* crypto, OSSL_ENCRYPTION_LEVEL level){
    if(crypto->offset + crypto->length <= context[level].crypto_want) {
        LOGD(DQUIC, "ignore dup crypto frame [%zd]\n", context[level].crypto_want);
        return PacketResult::ok;
    }
    if(crypto->offset > context[level].crypto_want) {
        LOGD(DQUIC, "skip unwanted crypto frame [%zd]\n", context[level].crypto_want);
        return PacketResult::skip;
    }
    uint8_t* start = (uint8_t*)crypto->body + (context[level].crypto_want - crypto->offset);
    size_t len = crypto->offset + crypto->length - context[level].crypto_want;
    SSL_provide_quic_data(ssl, level, start, len);
    context[level].crypto_want = crypto->offset + crypto->length;
    if(level == ssl_encryption_application){
        if(ssl_get_error(ssl, SSL_process_quic_post_handshake(ssl)) != 1){
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
            ErrorHE(PROTOCOL_ERR, error);
            return PacketResult::error;
        }
    }else {
        if(ssl_get_error(ssl, SSL_do_handshake(ssl)) == 1){
            LOGD(DQUIC, "SSL_do_handshake succeed\n");
            Connected(addrs.front());
            size_t olen = 0;
            const uint8_t* buff = nullptr;
            SSL_get_peer_quic_transport_params(ssl, &buff, &olen);
            const uint8_t* pos = buff;
            while(pos - buff < (int)olen){
                uint64_t name, size, value;
                pos += variable_decode(pos, &name);
                pos += variable_decode(pos, &size);
                switch(name){
                case quic_original_destination_connection_id:
                    break;
                case quic_max_idle_timeout:
                    variable_decode(pos, &value);
                    if(value < max_idle_timeout){
                        max_idle_timeout = value;
                    }
                    break;
                case quic_stateless_reset_token:
                    break;
                case quic_max_udp_payload_size:
                    variable_decode(pos, &value);
                    if(value > 1200){
                        his_max_payload_size = value;
                    }
                    break;
                case quic_initial_max_data:
                    variable_decode(pos, &his_max_data);
                    break;
                case quic_initial_max_stream_data_bidi_local:
                    variable_decode(pos, &his_max_stream_data_bidi_local);
                    break;
                case quic_initial_max_stream_data_bidi_remote:
                    variable_decode(pos, &his_max_stream_data_bidi_remote);
                    break;
                case quic_initial_max_stream_data_uni:
                    variable_decode(pos, &his_max_stream_data_uni);
                    break;
                case quic_initial_max_streams_bidi:
                    variable_decode(pos, &his_max_streams_bidi);
                    break;
                case quic_initial_max_streams_uni:
                    variable_decode(pos, &his_max_streams_uni);
                    break;
                case quic_ack_delay_exponent:
                    variable_decode(pos, &context[ssl_encryption_application].pnNs->ack_delay_exponent);
                    break;
                case quic_max_ack_delay:
                    variable_decode(pos, &his_max_ack_delay);
                    break;
                case quic_disable_active_migration:
                case quic_preferred_address:
                case quic_active_connection_id_limit:
                case quic_initial_source_connection_id:
                case quic_retry_source_connection_id:
                default:
                    break;
                }
                pos += size;
            }
        }else if(errno != EAGAIN){
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
            ErrorHE(SSL_SHAKEHAND_ERR, error);
            return PacketResult::error;
        }
    }
    return PacketResult::ok;
}

bool QuicRWer::IsLocal(uint64_t id) {
    return (ctx == nullptr) == ((id&0x01) == 0x01);
}

bool QuicRWer::IsBidirect(uint64_t id) {
    return (id&0x02) == 0;
}

QuicRWer::iterator QuicRWer::OpenStream(uint64_t id) {
    if(streammap.count(id)){
        return streammap.find(id);
    }
    if(IsBidirect(id)){
        // Bidirectional
        if(IsLocal(id)){
            // this is a closed id
            return streammap.end();
        }
        for(auto i = nextRemoteBiId; i <= id; i += 4){
            QuicStreamStatus stat{};
            stat.my_max_data = my_max_stream_data_bidi_remote;
            stat.his_max_data = his_max_stream_data_bidi_local;
            streammap.emplace(id, stat);
        }
        if(id >= nextRemoteBiId){
            nextRemoteBiId = id + 4;
        }
    }else{
        // Unidirectional
        if(IsLocal(id)){
            // this is a closed id
            return streammap.end();
        }
        for(auto i = nextRemoteUbiId; i <= id; i += 4){
            QuicStreamStatus stat{};
            stat.my_max_data = my_max_stream_data_uni;
            stat.his_max_data = 0;
            streammap.emplace(id, stat);
        }
        if(id >= nextRemoteUbiId){
            nextRemoteUbiId = id + 4;
        }
    }
    return streammap.find(id);
}


PacketResult QuicRWer::handleStreamPacket(uint64_t type, const quic_stream *stream) {
    auto id = stream->id;
    auto itr = OpenStream(id);
    if(itr == streammap.end()){
        //it is a retransmissions pkg
        return PacketResult::ok;
    }
    auto& status = itr->second;

    if(type & QUIC_FRAME_STREAM_FIN_F){
        status.flags |= STREAM_FLAG_EOF;
        status.finSize = stream->offset + stream->length;
    }
    uint64_t want = status.rb.Offset() + status.rb.length();
    if(stream->offset + stream->length <= want){
        LOGD(DQUIC, "ignore dup data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset + stream->length, want);
        return PacketResult::ok;
    }
    if(stream->offset > want){
        LOGD(DQUIC, "skip unordered data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset, want);
        return PacketResult::skip;
    }
    const char* start = stream->data + (want - stream->offset);
    size_t len = stream->length + stream->offset - want;
    if(status.rb.put(start, len) < 0){
        ErrorHE(PROTOCOL_ERR, 0);
        return PacketResult::error;
    }
    want += len;
    rblen += len;
    my_received_data += len;
    LOGD(DQUIC, "received data [%" PRIu64"] <%" PRIu64"/%" PRIu64"> <%" PRIu64"/%" PRIu64">%s\n",
         id, want, status.my_max_data, my_received_data, my_max_data,
         (type & QUIC_FRAME_STREAM_FIN_F)?" EOF":"");
    return PacketResult::ok;
}

PacketResult QuicRWer::handlePacketBeforeHandshake(const quic_packet *packet) {
    auto& header = packet->header;
    if(header.meta.type == QUIC_PACKET_INITIAL){
        dcids[0].id = header.meta.scid;
    }
    auto level = getLevel(header.meta.type);
    auto& pnNs = context[level].pnNs;
    pnNs->pns.PushPn(header.pn);
    packet_tx = updatejob(packet_tx, std::bind(&QuicRWer::sendPacket, this) , 2);
    for(auto frame: packet->frames){
        //CRYPTO, ACK frames, or both. PING, PADDING, and CONNECTION_CLOSE frames
        switch(frame->type){
        case QUIC_FRAME_PADDING:
            break;
        case QUIC_FRAME_PING:
            LOGD(DQUIC, "> [%c] ping frame [%" PRIu64"]\n", pnNs->name, header.pn);
            pnNs->should_ack = true;
            break;
        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
            LOGD(DQUIC, "> [%c] ack frame [%" PRIu64"]: %" PRIu64"[%" PRIu64"]\n", pnNs->name,
                 header.pn, frame->ack.acknowledged, (frame->ack.delay << pnNs->ack_delay_exponent)/1000);
            pnNs->HandleAck(&frame->ack);
            break;
        case QUIC_FRAME_CRYPTO:{
            LOGD(DQUIC, "> [%c] crypto frame [%" PRIu64"]: %" PRIu64" - %" PRIu64"\n", pnNs->name,
                 header.pn, frame->crypto.offset, frame->crypto.offset+frame->crypto.length);
            pnNs->should_ack = true;
            auto ret = handleCryptoPacket(&frame->crypto, level);
            if(ret != PacketResult::ok){
                return ret;
            }
            break;}
        case QUIC_FRAME_CONNECTION_CLOSE:
            LOGD(DQUIC, "> [%c] close frame [%" PRIu64 "]: %" PRIu64 "\n",
                 pnNs->name, header.pn, frame->close.error);
            LOGE("peer closed connection: %" PRIu64 "\n", frame->close.error);
            ErrorHE(SSL_SHAKEHAND_ERR, (int)frame->close.error);
            return PacketResult::error;
        default:
            LOGE("[%d] unexpected frame: 0x%02x\n", level, (int)frame->type);
            ErrorHE(SSL_SHAKEHAND_ERR, EPROTO);
            return PacketResult::error;
        }
    }
    return PacketResult::ok;
}

PacketResult QuicRWer::handlePacket(const quic_packet *packet) {
    const quic_pkt_header* header = &packet->header;
    if(header->meta.type != QUIC_PACKET_1RTT){
        return handlePacketBeforeHandshake(packet);
    }
    packet_tx = updatejob(packet_tx, std::bind(&QuicRWer::sendPacket, this) , his_max_ack_delay);
    time_out = updatejob(time_out, std::bind(&QuicRWer::timedOut, this), max_idle_timeout);
    auto pnNs = context[ssl_encryption_application].pnNs;
    pnNs->pns.PushPn(header->pn);
    for(auto frame : packet->frames) {
        switch (frame->type) {
        case QUIC_FRAME_PADDING:
            break;
        case QUIC_FRAME_CRYPTO:{
            LOGD(DQUIC, "> [a] crypto frame [%" PRIu64"]: %" PRIu64" - %" PRIu64"\n",
                 header->pn, frame->crypto.offset, frame->crypto.offset+frame->crypto.length);
            pnNs->should_ack = true;
            auto ret = handleCryptoPacket(&frame->crypto, ssl_encryption_application);
            if(ret != PacketResult::ok){
                return ret;
            }
            break;}
        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_ECN:
            LOGD(DQUIC, "> [a] ack frame [%" PRIu64"]: %" PRIu64"[%" PRIu64"]\n",
                 header->pn, frame->ack.acknowledged, (frame->ack.delay << pnNs->ack_delay_exponent)/1000);
            pnNs->HandleAck(&frame->ack);
            break;
        case QUIC_FRAME_PING:
            LOGD(DQUIC, "> [a] ping frame [%" PRIu64"]\n", header->pn);
            pnNs->should_ack = true;
            break;
        case QUIC_FRAME_HANDSHAKE_DONE:
            LOGD(DQUIC, "> [a] handshake_done frame [%" PRIu64"]\n", header->pn);
            pnNs->should_ack = true;
            dropkey(ssl_encryption_handshake);
            break;
        case QUIC_FRAME_MAX_DATA:
            LOGD(DQUIC, "> [a] max data  [%" PRIu64"]: %" PRIu64"\n",
                 header->pn, frame->extra);
            pnNs->should_ack = true;
            if(frame->extra > his_max_data){
                his_max_data = frame->extra;
            }
            break;
        case QUIC_FRAME_MAX_STREAMS_BI:
            LOGD(DQUIC, "> [a] max stream_bi  [%" PRIu64"]: %" PRIu64"\n",
                 header->pn, frame->extra);
            pnNs->should_ack = true;
            if(frame->extra > his_max_streams_bidi){
                his_max_streams_bidi = frame->extra;
            }
            break;
        case QUIC_FRAME_MAX_STREAMS_UBI:
            LOGD(DQUIC, "> [a] max stream_ubi  [%" PRIu64"]: %" PRIu64"\n",
                 header->pn, frame->extra);
            pnNs->should_ack = true;
            if(frame->extra > his_max_streams_uni){
                his_max_streams_uni = frame->extra;
            }
            break;
        case QUIC_FRAME_CONNECTION_CLOSE:
        case QUIC_FRAME_CONNECTION_CLOSE_APP:
            LOGD(DQUIC, "> [a] close from [%" PRIu64"] code: %d, reason: %.*s\n",
                 header->pn, (int)frame->close.error,
                 (int)frame->close.reason_len, frame->close.reason);
            ErrorHE(PROTOCOL_ERR, (int)frame->close.error);
            break;
        default:
            if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
                LOGD(DQUIC, "> [a] data [%" PRIu64"/%" PRIu64"]: %" PRIu64" - %" PRIu64"\n",
                     header->pn, frame->stream.id,
                     frame->stream.offset, frame->stream.offset + frame->stream.length);
                pnNs->should_ack = true;
                auto ret = handleStreamPacket(frame->type, &frame->stream);
                if(ret != PacketResult::ok){
                    return ret;
                }
            }else{
                LOGD(DQUIC, "> [a] ignore frame [%" PRIu64"]: 0x%02x\n", header->pn, (int)frame->type);
            }
            break;
        }
    }
    return PacketResult::ok;
}


void QuicRWer::handleRetryPacket(const quic_pkt_header* header){
    LOGD(DQUIC, "> [r] retry packet, token len: %zd\n", header->meta.token.length());
    if(!initToken.empty()){
        //A client MUST accept and process at most one Retry packet for each connection attempt.
        //After the client has received and processed an Initial or Retry packet from the server,
        // it MUST discard any subsequent Retry packets that it receives.
        LOGD(DQUIC, "discard no first retry packet\n");
        return;
    }
    initToken = header->meta.token;
    dcids[0].id = header->meta.scid;
    auto& sctx = context[0];
    quic_generate_initial_key(1, dcids[0].id.data(), dcids[0].id.length(), &sctx.write_secret);
    quic_generate_initial_key(0, dcids[0].id.data(), dcids[0].id.length(), &sctx.read_secret);
    for(auto& i: sctx.pnNs->sendq){
        PushFrame(sctx.pnNs, i.frame);
    }
    sctx.pnNs->sendq.clear();
    con_failed_job = updatejob(con_failed_job, std::bind(&QuicRWer::connect, this), 3000);
}

ssize_t QuicRWer::Write(const void *buff, size_t len, uint64_t id) {
    assert(streammap.count(id));

    auto& status = streammap[id];
    LOGD(DQUIC, "< [a] data [%" PRIu64 "]: %zd - %zd <%" PRIu64"/%" PRIu64"\n",
         id, status.offset, status.offset + len,
         status.my_max_data, status.his_max_data);

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_STREAM_START_ID | QUIC_FRAME_STREAM_LEN_F;
    if(status.offset) {
        frame->type |= QUIC_FRAME_STREAM_OFF_F;
    }
    if(len == 0){
        frame->type |= QUIC_FRAME_STREAM_FIN_F;
        status.flags |= STREAM_FLAG_FIN;
    }
    frame->stream.id = id;
    frame->stream.length = len;
    frame->stream.offset =  status.offset;
    status.offset += len;
    frame->stream.data = new char[len];
    memcpy(frame->stream.data, buff, len);
    PushFrame(context[ssl_encryption_application].pnNs, frame);
    my_send_data += len;

    LOGD(DQUIC, "send data [%" PRIu64"]: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
         id, status.offset, status.his_max_data, my_send_data, his_max_data);
    if(IsIdle(id)){
        LOGD(DQUIC, "clean idle stream: %" PRIu64"\n", id);
        streammap.erase(id);
    }
    return (int)len;
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
    ssize_t ret = read(getFd(), buff, sizeof(buff));
    if(ret < 0){
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    LOGD(DQUIC, "read bytes from socket: %d\n", (int)ret);
    char* pos = buff;
    while(pos - buff < ret) {
        if(*pos == 0){
            pos++;
            continue;
        }
        quic_pkt_header header;
        header.meta.dcid = scids[scid_id].id;
        int body_len = unpack_meta(pos, ret + buff - pos, &header.meta);
        if(body_len < 0){
            LOGE("QUIC meta unpack failed\n");
            ErrorHE(PROTOCOL_ERR, EPROTO);
            return;
        }
        if(header.meta.dcid != scids[scid_id].id){
            LOG("QUIC discard unknown dcid\n");
            return;
        }
        if(header.meta.type == QUIC_PACKET_RETRY){
            handleRetryPacket(&header);
            break;
        }
        OSSL_ENCRYPTION_LEVEL level = getLevel(header.meta.type);
        if(!context[level].valid){
            LOG("quic key for level %d is invalid, discard it (%d).\n", level, body_len);
            pos += body_len;
            continue;
        }
        header.pn_acked = context[level].pnNs->largest_ack;
        const quic_secret* secret = &context[level].read_secret;
        auto frames = decode_packet(pos, body_len, &header, secret);
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
        LOGD(DQUIC, "push packet [%" PRIu64 "/%d] to queue\n", packet->header.pn, level);
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
    if(rlength()){
        ConsumeRData();
    }
}

void QuicRWer::Reset(uint64_t id, uint32_t code) {
    LOGD(DQUIC, "< [a] quic reset [%" PRIu64 "]: %" PRIu32"\n", id, code);
    if(streammap.count(id) == 0){
        return;
    }
    auto& status = streammap[id];
    status.flags |= STREAM_FLAG_RESET;
    if(status.flags & STREAM_FLAG_FIN){
        return;
    }
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_RESET_STREAM;
    frame->reset.id = id;
    frame->reset.error = code;
    frame->reset.fsize = status.offset;
    PushFrame(context[ssl_encryption_application].pnNs, frame);
}

size_t QuicRWer::rlength() {
    return rblen;
}

bool QuicRWer::IsIdle(uint64_t id){
    if(streammap.count(id) == 0){
        return true;
    }
    auto status = streammap[id];
    if(status.flags & STREAM_FLAG_RESET){
        return true;
    }
    if(status.rb.length()){
        return false;
    }
    if(status.flags & STREAM_FLAG_EOF && status.offset != status.finSize){
        return false;
    }
    if(IsBidirect(id)){
        return (status.flags & STREAM_FLAG_FIN) && (status.flags & STREAM_FLAG_EOF);
    }else if(IsLocal(id)){
        return status.flags & STREAM_FLAG_FIN;
    }else{
        return status.flags & STREAM_FLAG_EOF;
    }
}

void QuicRWer::ConsumeRData() {
    for(auto i = streammap.begin(); i != streammap.end();){
        auto& flags = i->second.flags;
        if(i->second.rb.length() == 0){
            i++;
            continue;
        }
        auto& rb = i->second.rb;
        char* buff = (char*)p_malloc(rb.length());
        buff_block wb{buff, rb.get(buff, rb.length()), 0, i->first};
        readCB(wb);
        LOGD(DQUIC, "consume data [%" PRIu64"]: %" PRIu64" - %" PRIu64"\n",
             i->first, rb.Offset(), rb.Offset() + wb.offset);
        rb.consume(wb.offset);
        rblen -= wb.offset;

        if(flags & STREAM_FLAG_EOF && i->second.finSize == rb.Offset()){
            buff_block ewb{(const void*)nullptr, 0, 0, i->first};
            readCB(ewb);
        }

        if(my_max_data - my_received_data <= 50 *1024 *1024){
            my_max_data += 50 *1024 *1024;
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_DATA;
            frame->extra = my_max_data;
            PushFrame(context[ssl_encryption_application].pnNs, frame);
        }
        if(IsIdle(i->first)){
            LOGD(DQUIC, "clean idle stream: %" PRIu64"\n", i->first);
            i = streammap.erase(i);
            continue;
        }
        auto shouldSendMaxStreamData = [](QuicStreamStatus& status) -> bool {
            uint64_t offset = status.rb.Offset() + status.rb.length();
            if(offset + status.rb.cap() - status.my_max_data < BUF_LEN){
                return false;
            }
            if(status.my_max_data - offset >= BUF_LEN){
                return false;
            }
            if((status.flags & STREAM_FLAG_EOF) && status.my_max_data >= status.finSize){
                return false;
            }
            return true;
        };
        if(shouldSendMaxStreamData(i->second)){
            i->second.my_max_data =  rb.Offset() + rb.length() + rb.cap();
            LOGD(DQUIC, "expand max_data for [%" PRIu64"]: %zd\n", i->first, (size_t)i->second.my_max_data);
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAM_DATA;
            frame->max_stream_data.id = i->first;
            frame->max_stream_data.max = i->second.my_max_data;
            PushFrame(context[ssl_encryption_application].pnNs, frame);
        }
        i++;
    }
}

uint64_t QuicRWer::CreateBiStream() {
    uint64_t id = nextLocalBiId;
    nextLocalBiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = my_max_stream_data_bidi_local;
    stat.his_max_data = his_max_stream_data_bidi_remote;
    streammap.emplace(id, stat);
    return id;
}

uint64_t QuicRWer::CreateUbiStream() {
    uint64_t id = nextLocalUbiId;
    nextLocalUbiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = 0;
    stat.his_max_data = his_max_stream_data_uni;
    streammap.emplace(id, stat);
    return id;
}

void QuicRWer::timedOut() {
    ErrorHE(QUIC_NO_ERROR, ETIME);
}

void QuicRWer::keepAlive() {
    quic_frame* ping = new quic_frame;
    ping->type = QUIC_FRAME_PING;
    PushFrame(context[ssl_encryption_application].pnNs, ping);
}
