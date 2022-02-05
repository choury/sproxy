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
 * 发端流量控制（stream/data）
 * Stateless Reset处理
 * 分包
 * 多地址，失败轮询重试
 * server端实现
 * check retry packet tag
 * 连接迁移
 * pmtu
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

void QuicRWer::dropkey(OSSL_ENCRYPTION_LEVEL level) {
    LOGD(DQUIC, "drop key for level: %d\n", level);
    assert(level != ssl_encryption_application);
    if(!contexts[level].hasKey){
        return;
    }
    contexts[level].hasKey = false;
    memset(&contexts[level].read_secret, 0, sizeof(quic_secret));
    memset(&contexts[level].write_secret, 0, sizeof(quic_secret));
    qos.DropKey(level);
}

QuicRWer::quic_context* QuicRWer::getContext(uint8_t type) {
    switch(type){
    case QUIC_PACKET_INITIAL:
        return &contexts[ssl_encryption_initial];
    case QUIC_PACKET_HANDSHAKE:
        return &contexts[ssl_encryption_handshake];
    case QUIC_PACKET_0RTT:
        return &contexts[ssl_encryption_early_data];
    case QUIC_PACKET_1RTT:
        return &contexts[ssl_encryption_application];
    default:
        abort();
    }
}

int QuicRWer::set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *read_secret,
                                  const uint8_t *write_secret, size_t secret_len) {
    LOGD(DQUIC, "set_secret: level %d, len: %zd\n", level, secret_len );
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    assert(secret_len <= 32);
    quic_secret_set_key(&rwer->contexts[level].read_secret, (const char*)read_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    quic_secret_set_key(&rwer->contexts[level].write_secret, (const char*)write_secret, SSL_CIPHER_get_id(SSL_get_current_cipher(ssl)));
    rwer->qos.GetKey(level);
    rwer->contexts[level].hasKey = true;
    //drop init key
    rwer->dropkey(ssl_encryption_initial);
    return 1;
}

int QuicRWer::send(OSSL_ENCRYPTION_LEVEL level, uint64_t number, uint64_t ack, const void *body, size_t len) {
    quic_pkt_header header;
    header.type = getPacketType(level);
    header.dcid = dcids[dcid_id].id;
    header.scid = scids[scid_id].id;
    header.version = QUIC_VERSION_1;
    header.token = initToken;

    header.pn = number;
    header.pn_length = 4;
    header.pn_acked = ack;
    const quic_secret* secret = &contexts[level].write_secret;

    char packet[max_datagram_size];
    char* pos = encode_packet(body, len, &header, secret, packet);
    if(pos == nullptr){
        LOGE("QUIC failed to pack packet");
        return -QUIC_FRAME_ENCODING_ERROR;
    }
    size_t packet_len = pos - packet;
    if(header.type == QUIC_PACKET_INITIAL && packet_len < QUIC_INITIAL_LIMIT){
        memset(pos, 0, packet + QUIC_INITIAL_LIMIT - pos);
        packet_len = QUIC_INITIAL_LIMIT;
    }

    ssize_t ret = write(getFd(), packet, packet_len);
    if(ret < 0 && errno != EAGAIN){
        LOGE("QUIC failed to send packet to fd: %s\n", strerror(errno));
        return -QUIC_INTERNAL_ERROR;
    }
    return packet_len;
}

int QuicRWer::add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len) {
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    quic_context* context = &rwer->contexts[level];

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CRYPTO;
    frame->crypto.body = new char[len];
    memcpy(frame->crypto.body, data, len);
    frame->crypto.offset = context->crypto_offset;
    frame->crypto.length = len;
    rwer->qos.PushFrame(level, frame);
    context->crypto_offset += len;
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
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CONNECTION_CLOSE;
    frame->close.error = 0x100 + alert;
    frame->close.frame_type = QUIC_FRAME_CRYPTO;
    frame->close.reason_len = 0;
    frame->close.reason = nullptr;

    LOGD(DQUIC, "[%d] cc ssl send_alert: %d\n", level, alert);
    rwer->qos.PushFrame(level, frame);
    rwer->ErrorHE(PROTOCOL_ERR, QUIC_CRYPTO_ERROR);
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
    quic_generate_initial_key(1, dcid.id.data(), dcid.id.length(), &contexts[0].write_secret);
    quic_generate_initial_key(0, dcid.id.data(), dcid.id.length(), &contexts[0].read_secret);

    scids.push_back(scid);
    dcids.push_back(dcid);

    contexts[0].hasKey = true;
    contexts[0].level = ssl_encryption_initial;
    contexts[1].level = ssl_encryption_early_data;
    contexts[2].level = ssl_encryption_handshake;
    contexts[3].level = ssl_encryption_application;

    qos.GetKey(ssl_encryption_initial);
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
        SocketRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB)),
        qos(ctx != nullptr,
           std::bind(&QuicRWer::send, this, _1, _2, _3, _4, _5),
           std::bind(&QuicRWer::resendFrames, this, _1, _2))
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
    deljob(&keepAlive_timer);
    deljob(&close_timer);
    for(auto& context: contexts) {
        for (auto i: context.recvq) {
            frame_release(i.second);
        }
    }
}

void QuicRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        int error  = checkSocket(__PRETTY_FUNCTION__);
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&QuicRWer::connectFailed, this, error), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        assert(!addrs.empty());
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
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&QuicRWer::connectFailed, this, ETIMEDOUT), 2000);
    }
}

QuicRWer::FrameResult QuicRWer::handleCryptoFrame(quic_context* context, const quic_crypto* crypto){
    if(crypto->offset + crypto->length <= context->crypto_want) {
        LOGD(DQUIC, "ignore dup crypto frame [%zd]\n", context->crypto_want);
        return FrameResult::ok;
    }
    if(crypto->offset > context->crypto_want) {
        LOGD(DQUIC, "skip unwanted crypto frame [%zd]\n", context->crypto_want);
        return FrameResult::skip;
    }
    uint8_t* start = (uint8_t*)crypto->body + (context->crypto_want - crypto->offset);
    size_t len = crypto->offset + crypto->length - context->crypto_want;
    SSL_provide_quic_data(ssl, context->level, start, len);
    context->crypto_want = crypto->offset + crypto->length;
    if(context->level == ssl_encryption_application){
        if(ssl_get_error(ssl, SSL_process_quic_post_handshake(ssl)) != 1){
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
            ErrorHE(PROTOCOL_ERR, error);
            return FrameResult::error;
        }
    }else {
        if(ssl_get_error(ssl, SSL_do_handshake(ssl)) == 1){
            LOGD(DQUIC, "SSL_do_handshake succeed\n");
            Connected(addrs.front());
            size_t olen = 0;
            his_max_ack_delay = 25;
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
                    variable_decode(pos, &qos.GetNamespace(ssl_encryption_application)->ack_delay_exponent);
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
            qos.his_max_ack_delay = his_max_ack_delay;
        }else if(errno != EAGAIN){
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
            ErrorHE(SSL_SHAKEHAND_ERR, error);
            return FrameResult::error;
        }
    }
    return FrameResult::ok;
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


QuicRWer::FrameResult QuicRWer::handleStreamFrame(uint64_t type, const quic_stream *stream) {
    auto id = stream->id;
    auto itr = OpenStream(id);
    if(itr == streammap.end()){
        //it is a retransmissions pkg
        return FrameResult::ok;
    }
    auto& status = itr->second;

    uint64_t want = status.rb.Offset() + status.rb.length();
    if(type & QUIC_FRAME_STREAM_FIN_F){
        status.flags |= STREAM_FLAG_EOF;
        status.finSize = stream->offset + stream->length;
    }
    if(stream->offset + stream->length <= want){
        LOGD(DQUIC, "ignore dup data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset + stream->length, want);
        return FrameResult::ok;
    }
    if(stream->offset > want){
        LOGD(DQUIC, "skip unordered data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset, want);
        return FrameResult::skip;
    }
    const char* start = stream->data + (want - stream->offset);
    size_t len = stream->length + stream->offset - want;
    if(status.rb.put(start, len) < 0){
        ErrorHE(PROTOCOL_ERR, QUIC_FLOW_CONTROL_ERROR);
        return FrameResult::error;
    }
    want += len;
    rblen += len;
    my_received_data += len;
    LOGD(DQUIC, "received data [%" PRIu64"] <%" PRIu64"/%" PRIu64"> <%" PRIu64"/%" PRIu64">%s\n",
         id, want, status.my_max_data, my_received_data, my_max_data,
         (type & QUIC_FRAME_STREAM_FIN_F)?" EOF":"");

    ConsumeRData();
    return FrameResult::ok;
}

QuicRWer::FrameResult QuicRWer::handleResetFrame(const quic_reset *stream) {
    auto id = stream->id;
    auto itr = OpenStream(id);
    if(itr == streammap.end()){
        //it is a retransmissions/unordered pkg
        return FrameResult::ok;
    }
    auto& status = itr->second;
    uint64_t want = status.rb.Offset() + status.rb.length();

    if((status.flags & STREAM_FLAG_EOF) && want == status.finSize){
        LOGD(DQUIC, "ignored reset [%" PRIu64"]: after fin\n", id);
        return FrameResult::ok;
    }
    if(status.flags & STREAM_FLAG_RESET_RECVD) {
        return FrameResult::ok;
    }
    //TODO: remove data from rb
    status.flags |= STREAM_FLAG_RESET_RECVD;
    status.finSize = stream->fsize;

    if(want > status.finSize){
        ErrorHE(PROTOCOL_ERR, QUIC_FINAL_SIZE_ERROR);
        return FrameResult::error;
    }
    my_received_data += status.finSize - want;
    return FrameResult::ok;
}

QuicRWer::FrameResult QuicRWer::handleHandshakeFrames(quic_context *context, const quic_frame *frame) {
    //CRYPTO, ACK frames, or both. PING, PADDING, and CONNECTION_CLOSE frames
    switch (frame->type) {
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_PING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return FrameResult::ok;
    case QUIC_FRAME_CRYPTO:
        return handleCryptoFrame(context, &frame->crypto);
    case QUIC_FRAME_CONNECTION_CLOSE:
        flags |= RWER_CLOSING;
        ErrorHE(SSL_SHAKEHAND_ERR, (int) frame->close.error);
        return FrameResult::error;
    default:
        ErrorHE(SSL_SHAKEHAND_ERR, QUIC_PROTOCOL_VIOLATION);
        return FrameResult::error;
    }
}

int QuicRWer::handleHandshakePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    if(header->type == QUIC_PACKET_INITIAL){
        dcids[0].id = header->scid;
    }else{
        assert(header->type == QUIC_PACKET_HANDSHAKE);
    }
    auto context = getContext(header->type);
    for(auto frame: frames){
        qos.handleFrame(context->level, header->pn, frame);
        switch(handleHandshakeFrames(context, frame)){
        case FrameResult::ok:
            frame_release(frame);
            break;
        case FrameResult::skip:
            context->recvq.insert({header->pn, frame});
            break;
        case FrameResult::error:
            frame_release(frame);
            return 1;
        }
    }
    return 0;
}

int QuicRWer::handleRetryPacket(const quic_pkt_header* header){
    LOGD(DQUIC, "> [R] retry packet, token len: %zd\n", header->token.length());
    if(!initToken.empty()){
        //A client MUST accept and process at most one Retry packet for each connection attempt.
        //After the client has received and processed an Initial or Retry packet from the server,
        // it MUST discard any subsequent Retry packets that it receives.
        LOGD(DQUIC, "discard no first retry packet\n");
        return 0;
    }
    initToken = header->token;
    dcids[0].id = header->scid;
    auto& context = contexts[0];
    quic_generate_initial_key(1, dcids[0].id.data(), dcids[0].id.length(), &context.write_secret);
    quic_generate_initial_key(0, dcids[0].id.data(), dcids[0].id.length(), &context.read_secret);
    pn_namespace* pn = qos.GetNamespace(ssl_encryption_initial);
    for(auto& i: pn->sent_packets){
        for(auto frame: i.frames){
            qos.PushFrame(pn, frame);
        }
    }
    pn->sent_packets.clear();
    con_failed_job = updatejob(con_failed_job, std::bind(&QuicRWer::connect, this), 20000);
    return 0;
}

QuicRWer::FrameResult QuicRWer::handleFrames(quic_context *context, const quic_frame *frame) {
    switch (frame->type) {
    case QUIC_FRAME_CRYPTO:
        return handleCryptoFrame(context, &frame->crypto);
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_PING:
        return FrameResult::ok;
    case QUIC_FRAME_HANDSHAKE_DONE:
        dropkey(ssl_encryption_handshake);
        return FrameResult::ok;
    case QUIC_FRAME_MAX_DATA:
        if(frame->extra > his_max_data){
            his_max_data = frame->extra;
        }
        return FrameResult::ok;
    case QUIC_FRAME_DATA_BLOCKED:
        LOG("QUIC not implement data blocked frame, just ignore it\n");
        return FrameResult::ok;
    case QUIC_FRAME_MAX_STREAMS_BI:
        if(frame->extra > his_max_streams_bidi){
            his_max_streams_bidi = frame->extra;
        }
        return FrameResult::ok;
    case QUIC_FRAME_MAX_STREAMS_UBI:
        if(frame->extra > his_max_streams_uni){
            his_max_streams_uni = frame->extra;
        }
        return FrameResult::ok;
    case QUIC_FRAME_STOP_SENDING:
        OpenStream(frame->stop.id);
        LOG("QUIC not implement stop sending frame, just ignore it\n");
        return FrameResult::ok;
    case QUIC_FRAME_MAX_STREAM_DATA: {
        auto itr = OpenStream(frame->max_stream_data.id);
        if (itr == streammap.end()) {
            LOGD(DQUIC, "ignore not opened stream data\n");
            return FrameResult::ok;
        }
        if (frame->max_stream_data.max > itr->second.his_max_data) {
            itr->second.his_max_data = frame->max_stream_data.max;
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        OpenStream(frame->stream_data_blocked.id);
        LOG("QUIC not implement stream data blocked frame, just ignore it\n");
        return FrameResult::ok;
    case QUIC_FRAME_RESET_STREAM:
        return handleResetFrame(&frame->reset);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        flags |= RWER_CLOSING;
        ErrorHE(PROTOCOL_ERR, (int)frame->close.error);
        return FrameResult::error;
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            return handleStreamFrame(frame->type, &frame->stream);
        }
        return FrameResult::ok;
    }
}

void QuicRWer::resendFrames(pn_namespace* pn,quic_frame *frame) {
    switch(frame->type){
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_PING:
        frame_release(frame);
        break;
    case QUIC_FRAME_CRYPTO:
        qos.PushFrame(pn, frame);
        break;
    case QUIC_FRAME_HANDSHAKE_DONE:
        qos.PushFrame(pn, frame);
        break;
    case QUIC_FRAME_RESET_STREAM:
    case QUIC_FRAME_STOP_SENDING:
        //FIXME: as rfc9000#13.3
        qos.PushFrame(pn, frame);
        break;
    case QUIC_FRAME_MAX_DATA:
        frame->extra = my_max_data;
        qos.PushFrame(pn, frame);
        break;
    case QUIC_FRAME_MAX_STREAM_DATA:
        //FIXME: as rfc9000#13.3
        qos.PushFrame(pn, frame);
        break;
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            qos.PushFrame(pn, frame);
        }else {
            //FIXME: implement it
            qos.PushFrame(pn, frame);
        }
    }
}

int QuicRWer::handle1RttPacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    auto context = &contexts[ssl_encryption_application];
    keepAlive_timer = updatejob(keepAlive_timer, std::bind(&QuicRWer::keepAlive_action, this), 30000);
    for(auto frame : frames) {
        qos.handleFrame(context->level, header->pn, frame);
        switch(handleFrames(context, frame)){
        case FrameResult::ok:
            frame_release(frame);
            break;
        case FrameResult::skip:
            context->recvq.insert({header->pn, frame});
            break;
        case FrameResult::error:
            frame_release(frame);
            return 1;
        }
    }
    return 0;
}

int QuicRWer::handlePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    disconnect_timer = updatejob(disconnect_timer, std::bind(&QuicRWer::disconnect_action, this), max_idle_timeout);
    switch(header->type){
    case QUIC_PACKET_INITIAL:
    case QUIC_PACKET_HANDSHAKE:
        return handleHandshakePacket(header, frames);
    case QUIC_PACKET_RETRY:
        return handleRetryPacket(header);
    case QUIC_PACKET_1RTT:
        return handle1RttPacket(header, frames);
    case QUIC_PACKET_0RTT:
        LOGE("QUIC not implement 0-RTT packet type\n");
        return 0;
    default:
        LOGE("QUIC unknown packet type: %d\n", header->type);
        return 1;
    }
}

ssize_t QuicRWer::Write(const void *buff, size_t len, uint64_t id) {
    assert(streammap.count(id));

    auto& status = streammap[id];
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
    qos.PushFrame(ssl_encryption_application, frame);
    my_send_data += len;

    LOGD(DQUIC, "send data [%" PRIu64"]: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
         id, status.offset, status.his_max_data, my_send_data, his_max_data);
    if(IsIdle(id)){
        LOGD(DQUIC, "clean idle stream: %" PRIu64"\n", id);
        streammap.erase(id);
    }
    return (int)len;
}

void QuicRWer::closeHE(RW_EVENT events) {
    if(!(events & RW_EVENT::READ)) {
        return;
    }
    nextPackets([this](const quic_pkt_header* header, std::vector<const quic_frame*>& frames) -> int{
        LOGD(DQUIC, "[%" PRIu64"] discard packet after cc: %d\n", header->pn, header->type);
        for(auto frame : frames){
            frame_release(frame);
        }
        auto context = getContext(header->type);
        if(!context->hasKey){
            return 0;
        }
        quic_frame *frame = new quic_frame;
        frame->type = QUIC_FRAME_CONNECTION_CLOSE_APP;
        frame->close.error = QUIC_APPLICATION_ERROR;
        frame->close.frame_type = 0;
        frame->close.reason_len = 0;
        frame->close.reason = nullptr;
        qos.PushFrame(context->level, frame);
        close_timer = updatejob(close_timer, closeCB, 3 * qos.rtt.rttvar);
        return 0;
    });
}

void QuicRWer::Close(std::function<void()> func) {
    closeCB = std::move(func);
    if(getFd() >= 0 && stats != RWerStats::Connecting && stats != RWerStats::Error) {
        close_timer = updatejob(close_timer, closeCB, max_idle_timeout);
        handleEvent = (void (Ep::*)(RW_EVENT))&QuicRWer::closeHE;
        setEvents(RW_EVENT::READ);
        if(flags & RWER_CLOSING){
            return;
        }
        flags |= RWER_CLOSING;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_CONNECTION_CLOSE_APP;
        frame->close.error = QUIC_APPLICATION_ERROR;
        frame->close.frame_type = 0;
        frame->close.reason_len = 0;
        frame->close.reason = nullptr;
        qos.PushFrame(ssl_encryption_application, frame);
    }else{
        close_timer = updatejob(close_timer, closeCB, 0);
    }
}

void QuicRWer::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int QuicRWer::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

void QuicRWer::nextPackets(const std::function<
                int(const quic_pkt_header* header, std::vector<const quic_frame*>& frames)
                >& handler)
{
    char buff[max_datagram_size];
    while(true) {
        ssize_t ret = read(getFd(), buff, sizeof(buff));
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
        if(ret < 0) {
            ErrorHE(SOCKET_ERR, errno);
            return;
        }
        char *pos = buff;
        while (pos - buff < ret) {
            if (*pos == 0) {
                pos++;
                continue;
            }
            quic_pkt_header header;
            header.dcid = scids[scid_id].id;
            int body_len = unpack_meta(pos, ret + buff - pos, &header);
            if (body_len < 0) {
                LOGE("QUIC meta unpack failed, disacrd it\n");
                return;
            }
            if (header.dcid != scids[scid_id].id) {
                LOG("QUIC discard unknown dcid\n");
                return;
            }
            pos += body_len;
            std::vector<const quic_frame*> frames;
            if (header.type != QUIC_PACKET_RETRY) {
                auto context = getContext(header.type);
                if (!context->hasKey) {
                    LOG("quic key for level %d is invalid, discard it (%d).\n", context->level, body_len);
                    continue;
                }
                header.pn_acked = qos.GetNamespace(context->level)->largest_acked_packet + 1;
                frames = decode_packet(pos - body_len, body_len, &header, &context->read_secret);
                if (frames.empty()) {
                    LOGE("QUIC packet unpack failed, discard it\n");
                    continue;
                }
            }
            LOGD(DQUIC, "recv packet [%" PRIu64"] for type: 0x%02x\n", header.pn, header.type);
            if(handler(&header, frames)) {
                return;
            }
        }
    }
}

void QuicRWer::ReadData() {
    nextPackets(std::bind(&QuicRWer::handlePacket, this, _1, _2));
    for(auto& context : contexts) {
        if(!context.hasKey){
            continue;
        }
        for (auto i = context.recvq.begin(); i != context.recvq.end();) {
            FrameResult ret = FrameResult::ok;
            if (context.level != ssl_encryption_application) {
                ret = handleHandshakeFrames(&context, i->second);
            } else {
                ret = handleFrames(&context, i->second);
            }
            switch (ret) {
            case FrameResult::ok:
                frame_release(i->second);
                i = context.recvq.erase(i);
                break;
            case FrameResult::skip:
                i++;
                break;
            case FrameResult::error:
                return;
            }
        }
    }
    if(rlength()){
        ConsumeRData();
    }
}

void QuicRWer::Reset(uint64_t id, uint32_t code) {
    if(streammap.count(id) == 0){
        return;
    }
    auto& status = streammap[id];
    if((status.flags & STREAM_FLAG_FIN)){
        return;
    }
    status.flags |= STREAM_FLAG_RESET_SENT;
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_RESET_STREAM;
    frame->reset.id = id;
    frame->reset.error = code;
    frame->reset.fsize = status.offset;
    qos.PushFrame(ssl_encryption_application, frame);
}

size_t QuicRWer::rlength() {
    return rblen;
}

bool QuicRWer::IsIdle(uint64_t id){
    if(streammap.count(id) == 0){
        return true;
    }
    auto status = streammap[id];
    bool send_closed = false;
    bool recv_closed = false;
    if((status.flags & STREAM_FLAG_FIN) || (status.flags & STREAM_FLAG_RESET_SENT)){
        send_closed = true;
    }
    if(status.flags & STREAM_FLAG_RESET_RECVD){
        recv_closed = true;
    }
    if((status.flags & STREAM_FLAG_EOF) && (status.rb.Offset() == status.finSize)){
        assert(status.rb.length() == 0);
        recv_closed = true;
    }

    if(IsBidirect(id)){
        return send_closed && recv_closed;
    }else if(IsLocal(id)){
        return send_closed;
    }else{
        return recv_closed;
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
        LOGD(DQUIC, "consume data [%" PRIu64"]: %" PRIu64" - %" PRIu64" [%zd]\n",
             i->first, rb.Offset(), rb.Offset() + wb.offset, i->second.rb.length());
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
            qos.PushFrame(ssl_encryption_application, frame);
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
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAM_DATA;
            frame->max_stream_data.id = i->first;
            frame->max_stream_data.max = i->second.my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
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

void QuicRWer::disconnect_action() {
    if(flags & RWER_CLOSING){
        return;
    }
    ErrorHE(PROTOCOL_ERR, QUIC_NO_ERROR);
}

void QuicRWer::keepAlive_action() {
    auto context = &contexts[ssl_encryption_application];
    assert(context->hasKey);
    if(flags & RWER_CLOSING){
        return;
    }
    qos.PushFrame(ssl_encryption_application, new quic_frame{QUIC_FRAME_PING, {}});
}
