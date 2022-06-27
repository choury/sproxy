//
// Created by 周威 on 2021/6/20.
//
#include "quicio.h"
#include "quic_mgr.h"
#include "quic_pack.h"
#include "misc/util.h"
#include "prot/tls.h"
#include <openssl/err.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

#include <set>

#if __ANDROID__
extern std::string getExternalFilesDir();
#endif

/*TODO:
 * 连接迁移
 * 多地址，失败轮询重试
 * check retry packet tag
 * pmtu
 */

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

void Recvq::insert(const quic_frame *frame) {
    auto i = data.begin();
    if(frame->type == QUIC_FRAME_CRYPTO){
        for(; i != data.end(); i++){
            if((*i)->crypto.offset < frame->crypto.offset){
                continue;
            }
            break;
        }
    } else {
        assert(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID);
        for(; i != data.end(); i++){
            if((*i)->stream.offset < frame->stream.offset){
                continue;
            }
            break;
        }
    }
    data.insert(i, frame);
}

Recvq::~Recvq() {
   for(auto i : data){
       frame_release(i);
   }
   data.clear();
}

void QuicRWer::dropkey(OSSL_ENCRYPTION_LEVEL level) {
    assert(level != ssl_encryption_application);
    if(!contexts[level].hasKey){
        return;
    }
    LOGD(DQUIC, "drop key for level: %d\n", level);
    contexts[level].hasKey = false;
    memset(&contexts[level].read_secret, 0, sizeof(quic_secret));
    memset(&contexts[level].write_secret, 0, sizeof(quic_secret));
    qos.KeyLost(level);
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
    rwer->qos.KeyGot(level);
    rwer->contexts[level].hasKey = true;
    if(rwer->ctx) {
        //drop init key if client mode
        rwer->dropkey(ssl_encryption_initial);
    }
    return 1;
}

size_t QuicRWer::envelopLen(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, size_t len){
    (void)pn;
    (void)ack;
    switch(level){
    case ssl_encryption_initial:
        return 7 /*flags(1)+version(4)+dcid_len(1)+scid_len(1)*/
            + hisids[hisid_idx].length() + myids[myid_idx].length()
               + variable_encode_len(initToken.length()) + initToken.length()
            + variable_encode_len(len) + 4 /*packet number*/ + 16/*crypto tag*/;
    case ssl_encryption_early_data:
    case ssl_encryption_handshake:
        return 7 + hisids[hisid_idx].length() + myids[myid_idx].length()
               + variable_encode_len(len) + 4 + 16;
    case ssl_encryption_application:
        return 1 + hisids[hisid_idx].length() + 4 + 16;
    }
    return 0;
}

int QuicRWer::send(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, const void *body, size_t len) {
    if(body == nullptr){
        return envelopLen(level, pn, ack, len);
    }
    quic_pkt_header header;
    header.type = getPacketType(level);
    header.dcid = hisids[hisid_idx];
    header.scid = myids[myid_idx];
    header.version = QUIC_VERSION_1;
    header.token = initToken;

    header.pn = pn;
    header.pn_length = 4;
    header.pn_base = ack;
    const quic_secret* secret = &contexts[level].write_secret;

    char packet[max_datagram_size];
    char* pos = encode_packet(body, len, &header, secret, packet);
    if(pos == nullptr){
        LOGE("QUIC failed to pack packet");
        return -QUIC_FRAME_ENCODING_ERROR;
    }
    size_t packet_len = pos - packet;
    if(header.type == QUIC_PACKET_INITIAL && packet_len < QUIC_INITIAL_LIMIT && ctx){
        memset(pos, 0, packet + QUIC_INITIAL_LIMIT - pos);
        packet_len = QUIC_INITIAL_LIMIT;
    }
    if(header.type == QUIC_PACKET_1RTT){
        LOGD(DQUIC, " <- %s [%" PRIu64"], type: 0x%02x, length: %d\n",
             dumpHex(header.scid.data(), header.scid.length()).c_str(),
             header.pn, header.type, (int) len);
    }else {
        LOGD(DQUIC, "%s <- %s [%" PRIu64"], type: 0x%02x, length: %d\n",
             dumpHex(header.dcid.data(), header.dcid.length()).c_str(),
             dumpHex(header.scid.data(), header.scid.length()).c_str(),
             header.pn, header.type, (int) len);
    }

    ssize_t ret = write(getFd(), packet, packet_len);
    if(ret < 0 && errno != EAGAIN){
        LOGE("QUIC failed to send packet to fd: %s\n", strerror(errno));
        return -QUIC_INTERNAL_ERROR;
    }
    my_sent_data_total += ret;
    return packet_len;
}

int QuicRWer::add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                              const uint8_t *data, size_t len) {
    QuicRWer* rwer = (QuicRWer*)SSL_get_app_data(ssl);
    quic_context* context = &rwer->contexts[level];

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CRYPTO;
    frame->crypto.buffer.ref = (uint32_t*)new char[len + sizeof(uint32_t)];
    frame->crypto.buffer.data = (char*)(frame->crypto.buffer.ref + 1);
    *frame->crypto.buffer.ref = 1;
    memcpy(frame->crypto.buffer.data, data, len);
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
    if(rwer->stats == RWerStats::Error || (rwer->flags | RWER_CLOSING)){
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
    std::string hisid, myid;
    myid.resize(QUIC_CID_LEN + 1);
    snprintf(&myid[0], myid.size(), "sproxy0000%010d", rand());
    set32(&myid[6], getutime());
    myid.resize(QUIC_CID_LEN);

    hisid.resize(QUIC_CID_LEN + 1);
    snprintf(&hisid[0], hisid.size(), "sproxy0000%010d", rand());
    set32(&hisid[6], getutime());
    hisid.resize(QUIC_CID_LEN);

    myids.push_back(myid);
    hisids.push_back(hisid);
    histoken.push_back("");

    if(ctx) {
        //only client has init secret now.
        quic_generate_initial_key(1, hisid.data(), hisid.length(), &contexts[0].write_secret);
        quic_generate_initial_key(0, hisid.data(), hisid.length(), &contexts[0].read_secret);
        qos.KeyGot(ssl_encryption_initial);
        contexts[0].hasKey = true;
    }

    contexts[0].level = ssl_encryption_initial;
    contexts[1].level = ssl_encryption_early_data;
    contexts[2].level = ssl_encryption_handshake;
    contexts[3].level = ssl_encryption_application;

}

size_t QuicRWer::generateParams(char data[QUIC_INITIAL_LIMIT]) {
    char* pos = data;
    pos += variable_encode(pos, quic_initial_source_connection_id);
    pos += variable_encode(pos, myids[0].length());
    memcpy(pos, myids[0].data(), myids[0].length());
    pos += myids[0].length();
    if(!originDcid.empty()) {
        pos += variable_encode(pos, quic_original_destination_connection_id);
        pos += variable_encode(pos, originDcid.length());
        memcpy(pos, originDcid.data(), originDcid.length());
        pos += originDcid.length();
    }
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
    if(ctx != nullptr) {
        return pos - data;
    }
    pos += variable_encode(pos, quic_disable_active_migration);
    pos += variable_encode(pos, 0);

    std::string token = sign_cid(myids[0]);
    if(!token.empty()){
        pos += variable_encode(pos, quic_stateless_reset_token);
        pos += variable_encode(pos, token.size());
        memcpy(pos, token.data(), token.size());
        pos += token.size();
    }
    return pos - data;
}

QuicRWer::QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                   std::function<void(int, int)> errorCB,
                   std::function<void(const sockaddr_storage&)> connectCB):
        SocketRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB)),
        qos(false, std::bind(&QuicRWer::send, this, _1, _2, _3, _4, _5),
           std::bind(&QuicRWer::resendFrames, this, _1, _2),
           std::bind(&QuicRWer::ErrorHE, this, PROTOCOL_ERR, _1))
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
    if (SSL_CTX_load_verify_locations(ctx, (getExternalFilesDir() + CABUNDLE).c_str(), "/etc/security/cacerts/") != 1)
#else
    if (SSL_CTX_load_verify_locations(ctx, CABUNDLE, "/etc/ssl/certs/") != 1)
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
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);
    nextLocalBiId   = 0;
    nextRemoteBiId  = 1;
    nextLocalUbiId  = 2;
    nextRemoteUbiId = 3;
    walkHandler = std::bind(&QuicRWer::handlePacket, this, _1, _2);
}

QuicRWer::QuicRWer(int fd, const sockaddr_storage *peer, SSL_CTX *ctx, QuicMgr* mgr,
                   std::function<void(int, int)> errorCB,
                   std::function<void(const sockaddr_storage &)> connectCB):
        SocketRWer(fd, peer, std::move(errorCB)), mgr(mgr),
        qos(true, std::bind(&QuicRWer::send, this, _1, _2, _3, _4, _5),
            std::bind(&QuicRWer::resendFrames, this, _1, _2),
            std::bind(&QuicRWer::ErrorHE, this, PROTOCOL_ERR, _1))
{
    this->connectCB = std::move(connectCB);
    ssl = SSL_new(ctx);
    SSL_set_quic_method(ssl, &quic_method);
    if(ssl == nullptr){
        LOGF("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_set_app_data(ssl, this);
    generateCid();
    SSL_set_accept_state(ssl);
    stats = RWerStats::SslAccepting;
    nextLocalBiId   = 1;
    nextRemoteBiId  = 0;
    nextLocalUbiId  = 3;
    nextRemoteUbiId = 2;
    walkHandler = std::bind(&QuicRWer::handlePacket, this, _1, _2);
    setEvents(RW_EVENT::READ);
    mgr->rwers.emplace(myids[0], this);
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
    if(mgr == nullptr){
        return;
    }
    for(auto id: myids){
        mgr->rwers.erase(id);
    }
    mgr->rwers.erase(originDcid);
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

        char quic_params[QUIC_INITIAL_LIMIT];
        SSL_set_quic_transport_params(ssl, (const uint8_t*)quic_params, generateParams(quic_params));
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
        LOGD(DQUIC, "skip unwanted crypto frame [%zd/%" PRIu64"]\n", context->crypto_want, crypto->offset);
        return FrameResult::skip;
    }
    uint8_t* start = (uint8_t*)crypto->buffer.data + (context->crypto_want - crypto->offset);
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
                    if(value < max_idle_timeout && value > 0){
                        max_idle_timeout = value;
                    }
                    break;
                case quic_stateless_reset_token:
                    assert(size == QUIC_TOKEN_LEN);
                    histoken[0] = std::string((char*)pos, QUIC_TOKEN_LEN);
                    break;
                case quic_max_udp_payload_size:
                    variable_decode(pos, &value);
                    if(value > 1200){
                        his_max_payload_size = value;
                    }
                    break;
                case quic_initial_max_data:
                    variable_decode(pos, &value);
                    if(value > his_max_data){
                        his_max_data = value;
                    }
                    break;
                case quic_initial_max_stream_data_bidi_local:
                    variable_decode(pos, &value);
                    if(value > his_max_stream_data_bidi_local){
                        his_max_stream_data_bidi_local = value;
                    }
                    break;
                case quic_initial_max_stream_data_bidi_remote:
                    variable_decode(pos, &value);
                    if(value > his_max_stream_data_bidi_remote){
                        his_max_stream_data_bidi_remote = value;
                    }
                    break;
                case quic_initial_max_stream_data_uni:
                    variable_decode(pos, &value);
                    if(value > his_max_stream_data_uni){
                        his_max_stream_data_uni = value;
                    }
                    break;
                case quic_initial_max_streams_bidi:
                    variable_decode(pos, &value);
                    if(value > his_max_streams_bidi) {
                        his_max_streams_bidi = value;
                    }
                    break;
                case quic_initial_max_streams_uni:
                    variable_decode(pos, &value);
                    if(value > his_max_streams_uni) {
                        his_max_streams_uni = value;
                    }
                    break;
                case quic_ack_delay_exponent:{
                    uint64_t ack_delay_exponent;
                    variable_decode(pos, &ack_delay_exponent);
                    qos.SetAckDelayExponent(ack_delay_exponent);
                    break;
                }
                case quic_max_ack_delay:
                    variable_decode(pos, &his_max_ack_delay);
                    break;
                case quic_disable_active_migration:
                case quic_preferred_address:
                case quic_active_connection_id_limit:
                case quic_initial_source_connection_id:
                case quic_retry_source_connection_id:
                    LOG("unimplemented params: %" PRIu64"\n", name);
                    break;
                default:
                    break;
                }
                pos += size;
            }
            qos.SetMaxAckDelay(his_max_ack_delay);
            if(ctx == nullptr){
                //send handshake done frame to client
                qos.PushFrame(ssl_encryption_application, new quic_frame{QUIC_FRAME_HANDSHAKE_DONE, {}});
                dropkey(ssl_encryption_handshake);
            }else{
                //discard token from retry packet.
                initToken.clear();
            }
            Connected(addrs.front());
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
            streammap.emplace(id, std::move(stat));
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
            streammap.emplace(id, std::move(stat));
        }
        if(id >= nextRemoteUbiId){
            nextRemoteUbiId = id + 4;
        }
    }
    return streammap.find(id);
}

void QuicRWer::CleanStream(uint64_t id) {
    assert(idle(id));
    LOGD(DQUIC, "clean idle stream: %" PRIu64"\n", id);
    for(auto i = fullq.begin(); i != fullq.end(); ){
        if((*i)->stream.id != id) {
            i++;
            continue;
        }
        frame_release(*i);
        i = fullq.erase(i);
    }
    if(streammap.count(id)){
        streammap.erase(id);
    }
}


QuicRWer::FrameResult QuicRWer::handleStreamFrame(uint64_t type, const quic_stream *stream) {
    auto id = stream->id;
    auto itr = OpenStream(id);
    if(itr == streammap.end()){
        //it is a retransmissions pkg
        return FrameResult::ok;
    }
    auto& status = itr->second;
    if(status.flags & STREAM_FLAG_RESET_RECVD){
        // discard all data after reset
        return FrameResult::ok;
    }

    uint64_t want = status.rb.Offset() + status.rb.length();
    if(type & QUIC_FRAME_STREAM_FIN_F){
        status.flags |= STREAM_FLAG_FIN_RECVD;
        status.finSize = stream->offset + stream->length;

        if(std::max(stream->offset + stream->length, want) > status.finSize) {
            ErrorHE(PROTOCOL_ERR, QUIC_FINAL_SIZE_ERROR);
            return FrameResult::error;
        }
    }
    uint64_t his_offset = stream->offset + stream->length;
    if(his_offset > status.his_offset) {
        status.his_offset = his_offset;
    }

    if(his_offset <= want){
        LOGD(DQUIC, "ignore dup data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset + stream->length, want);
        return FrameResult::ok;
    }
    if(stream->offset > want){
        LOGD(DQUIC, "skip unordered data [%" PRIu64"]: %" PRIu64"/%" PRIu64"\n",
             id, stream->offset, want);
        return FrameResult::skip;
    }
    const char* start = stream->buffer.data + (want - stream->offset);
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

    //ConsumeRData();
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

    if((status.flags & STREAM_FLAG_FIN_RECVD) && want == stream->fsize){
        LOGD(DQUIC, "ignored reset [%" PRIu64"]: after fin\n", id);
        return FrameResult::ok;
    }
    if(status.flags & STREAM_FLAG_RESET_RECVD) {
        //duplicate reset, may be retransmissions
        return FrameResult::ok;
    }

    if(want > stream->fsize){
        ErrorHE(PROTOCOL_ERR, QUIC_FINAL_SIZE_ERROR);
        return FrameResult::error;
    }

    status.flags |= STREAM_FLAG_FIN_RECVD | STREAM_FLAG_RESET_RECVD;
    status.finSize = stream->fsize;
    my_received_data += status.finSize - want;
    status.rb.consume(status.rb.length());

    if((status.flags & STREAM_FLAG_RESET_DELIVED) == 0) {
        status.flags |= STREAM_FLAG_RESET_DELIVED;
        if (resetHandler) {
            resetHandler(id, stream->error);
        }
    }
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
        hisids[0] = header->scid;
    }else{
        assert(header->type == QUIC_PACKET_HANDSHAKE);
        dropkey(ssl_encryption_initial);
    }
    auto context = getContext(header->type);
    for(auto frame: frames){
        qos.handleFrame(context->level, header->pn, frame);
        switch(handleHandshakeFrames(context, frame)){
        case FrameResult::ok:
            frame_release(frame);
            break;
        case FrameResult::skip:
            context->recvq.insert(frame);
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
    hisids[0] = header->scid;
    auto& context = contexts[0];
    quic_generate_initial_key(1, hisids[0].data(), hisids[0].length(), &context.write_secret);
    quic_generate_initial_key(0, hisids[0].data(), hisids[0].length(), &context.read_secret);
    qos.HandleRetry();
    con_failed_job = updatejob(con_failed_job, std::bind(&QuicRWer::connect, this), 20000);
    return 0;
}

QuicRWer::FrameResult QuicRWer::handleFrames(quic_context *context, const quic_frame *frame) {
    switch (frame->type) {
    case QUIC_FRAME_CRYPTO:
        return handleCryptoFrame(context, &frame->crypto);
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_PING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return FrameResult::ok;
    case QUIC_FRAME_HANDSHAKE_DONE:
        dropkey(ssl_encryption_handshake);
        return FrameResult::ok;
    case QUIC_FRAME_MAX_DATA:
        if(frame->extra > his_max_data){
            his_max_data = frame->extra;
        }
        return FrameResult::ok;
    case QUIC_FRAME_DATA_BLOCKED: {
        if(my_max_data - my_received_data <= 50 *1024 *1024){
            my_max_data += 50 *1024 *1024;
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_DATA;
            frame->extra = my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
        }
        return FrameResult::ok;
    }
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
    case QUIC_FRAME_STOP_SENDING: {
        auto itr = OpenStream(frame->stop.id);
        if(itr == streammap.end()){
            return FrameResult::ok;
        }
        auto& status = itr->second;
        if((status.flags & STREAM_FLAG_FIN_SENT) == 0){
            status.flags |= STREAM_FLAG_FIN_SENT;
            quic_frame* reset = new quic_frame;
            reset->type = QUIC_FRAME_RESET_STREAM;
            reset->reset.id = frame->stop.id;
            reset->reset.fsize = status.my_offset;
            reset->reset.error = frame->stop.error;
            qos.PushFrame(ssl_encryption_application, reset);
        }
        if((status.flags & STREAM_FLAG_RESET_DELIVED) == 0){
            status.flags |= STREAM_FLAG_RESET_DELIVED;
            if(resetHandler){
                resetHandler(frame->stop.id, frame->stop.error);
            }
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_MAX_STREAM_DATA: {
        auto itr = OpenStream(frame->max_stream_data.id);
        if (itr == streammap.end()) {
            LOGD(DQUIC, "ignore not opened stream data\n");
            return FrameResult::ok;
        }
        auto new_max_data = frame->max_stream_data.max;
        auto& status = itr->second;
        if (new_max_data <= status.his_max_data) {
            return FrameResult::ok;
        }
        for(auto i = fullq.begin(); i != fullq.end(); ){
            assert((*i)->type >= QUIC_FRAME_STREAM_START_ID && (*i)->type <= QUIC_FRAME_STREAM_END_ID);
            if((*i)->stream.id != itr->first){
                i++;
                continue;
            }
            if((*i)->stream.offset + (*i)->stream.length > new_max_data) {
                break;
            }
            qos.PushFrame(ssl_encryption_application, *i);
            i = fullq.erase(i);
        }
        status.his_max_data = new_max_data;
        if(new_max_data >= status.my_offset) {
            //这里如果max_data大于offset的话，那么fullq里面就应该不存在这个流的包了
            if(idle(itr->first)){
                CleanStream(itr->first);
            }else{
                writeCB(itr->first);
            }
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_STREAM_DATA_BLOCKED:{
        auto itr = OpenStream(frame->stream_data_blocked.id);
        if (itr == streammap.end()) {
            LOGD(DQUIC, "ignore not opened stream data\n");
            return FrameResult::ok;
        }
        auto &rb = itr->second.rb;
        auto my_max_data = rb.Offset() + rb.length() + rb.cap();
        if(my_max_data > itr->second.my_max_data) {
            itr->second.my_max_data = my_max_data;
            quic_frame *frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAM_DATA;
            frame->max_stream_data.id = itr->first;
            frame->max_stream_data.max = my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_RESET_STREAM:
        return handleResetFrame(&frame->reset);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        flags |= RWER_CLOSING;
        ErrorHE(PROTOCOL_ERR, (int)frame->close.error);
        return FrameResult::error;
    case QUIC_FRAME_NEW_TOKEN:
        if(ctx == nullptr){
            LOGE("Get new token from client\n");
            ErrorHE(PROTOCOL_ERR, QUIC_PROTOCOL_VIOLATION);
            return FrameResult::error;
        }else {
            initToken = frame->new_token.token;
            return FrameResult::ok;
        }
    case QUIC_FRAME_NEW_CONNECTION_ID:
        if(frame->new_id.retired > frame->new_id.seq){
            ErrorHE(PROTOCOL_ERR, QUIC_FRAME_ENCODING_ERROR);
            return FrameResult::error;
        }
        hisids.resize(frame->new_id.seq + 1);
        histoken.resize(frame->new_id.seq + 1);
        hisids[frame->new_id.seq] = std::string(frame->new_id.id, frame->new_id.length);
        histoken[frame->new_id.seq] = std::string(frame->new_id.token, QUIC_TOKEN_LEN);
        for(auto i = hisid_idx; i < frame->new_id.retired; i++){
            quic_frame* frame = new quic_frame{QUIC_FRAME_RETIRE_CONNECTION_ID, {}};
            frame->extra = i;
            qos.PushFrame(ssl_encryption_application, frame);
        }
        hisid_idx = frame->new_id.retired;
        return FrameResult::ok;
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        if(frame->extra >  myids.size()){
            ErrorHE(PROTOCOL_ERR, QUIC_PROTOCOL_VIOLATION);
            return FrameResult::error;
        }
        if(mgr) {
            mgr->rwers.erase(myids[frame->extra]);
        }
        return FrameResult::ok;
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            return handleStreamFrame(frame->type, &frame->stream);
        }
        return FrameResult::ok;
    }
}

void QuicRWer::resendFrames(pn_namespace* ns, quic_frame *frame) {
    switch(frame->type){
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_PING:
        frame_release(frame);
        break;
    case QUIC_FRAME_CRYPTO:
        qos.FrontFrame(ns, frame);
        break;
    case QUIC_FRAME_HANDSHAKE_DONE:
        qos.FrontFrame(ns, frame);
        break;
    case QUIC_FRAME_RESET_STREAM:
    case QUIC_FRAME_STOP_SENDING:
        //FIXME: as rfc9000#13.3
        qos.FrontFrame(ns, frame);
        break;
    case QUIC_FRAME_MAX_DATA:
        frame->extra = my_max_data;
        qos.FrontFrame(ns, frame);
        break;
    case QUIC_FRAME_MAX_STREAM_DATA: {
        uint64_t id = frame->max_stream_data.id;
        if(streammap.count(id) == 0){
            frame_release(frame);
            break;
        }
        auto& status = streammap.find(id)->second;
        status.my_max_data =  status.rb.Offset() + status.rb.length() + status.rb.cap();
        frame->max_stream_data.max = status.my_max_data;
        qos.FrontFrame(ns, frame);
        break;
    }
    case QUIC_FRAME_DATA_BLOCKED:
        if(my_sent_data < his_max_data){
            frame_release(frame);
            break;
        }
        frame->extra = my_sent_data;
        qos.FrontFrame(ns, frame);
        break;
    case QUIC_FRAME_STREAM_DATA_BLOCKED:{
        uint64_t id = frame->stream_data_blocked.id;
        if(streammap.count(id) == 0){
            frame_release(frame);
            break;
        }
        auto& status = streammap.find(id)->second;
        if(status.my_offset < status.his_max_data){
            frame_release(frame);
            break;
        }
        frame->stream_data_blocked.size = status.my_offset;
        qos.FrontFrame(ns, frame);
        break;
    }
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            qos.FrontFrame(ns, frame);
        }else {
            //FIXME: implement other frame type resend logic
            qos.FrontFrame(ns, frame);
        }
    }
}

int QuicRWer::handle1RttPacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    auto context = &contexts[ssl_encryption_application];
    keepAlive_timer = updatejob(keepAlive_timer,
                                std::bind(&QuicRWer::keepAlive_action, this),
                                std::min(30000, (int)max_idle_timeout/2));
    for(auto frame : frames) {
        qos.handleFrame(context->level, header->pn, frame);
        switch(handleFrames(context, frame)){
        case FrameResult::ok:
            frame_release(frame);
            break;
        case FrameResult::skip:
            //有丢包，立即发送ack
            qos.SendNow();
            context->recvq.insert(frame);
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
    if(stats == RWerStats::Error){
        return 0;
    }
    assert(streammap.count(id));

    auto& status = streammap[id];
    assert((status.flags & STREAM_FLAG_FIN_SENT) == 0);
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_STREAM_START_ID | QUIC_FRAME_STREAM_LEN_F;
    if(status.my_offset) {
        frame->type |= QUIC_FRAME_STREAM_OFF_F;
    }
    if(len == 0){
        frame->type |= QUIC_FRAME_STREAM_FIN_F;
        status.flags |= STREAM_FLAG_FIN_SENT;
    }
    frame->stream.id = id;
    frame->stream.length = len;
    frame->stream.offset =  status.my_offset;
    frame->stream.buffer.ref = (uint32_t*)new char[len + sizeof(uint32_t)];
    frame->stream.buffer.data = (char*)(frame->stream.buffer.ref + 1);
    *frame->stream.buffer.ref = 1;
    memcpy(frame->stream.buffer.data, buff, len);
    my_sent_data += len;
    assert(my_sent_data <= his_max_data);

    status.my_offset += len;
    if(status.my_offset > status.his_max_data){
        quic_frame* block = new quic_frame{QUIC_FRAME_STREAM_DATA_BLOCKED, {}};
        block->stream_data_blocked.id = id;
        block->stream_data_blocked.size = status.my_offset;
        qos.PushFrame(ssl_encryption_application, block);
        fullq.push_back(frame);
        LOGD(DQUIC, "push data [%" PRIu64"] to fullq: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
             id, status.my_offset, status.his_max_data, my_sent_data, his_max_data);
        return (int)len;
    }
    qos.PushFrame(ssl_encryption_application, frame);
    LOGD(DQUIC, "send data [%" PRIu64"]: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
         id, status.my_offset, status.his_max_data, my_sent_data, his_max_data);
    if(idle(id)){
        CleanStream(id);
    }else{
        writeCB(id);
    }
    return (int)len;
}

buff_iterator QuicRWer::buffer_insert(buff_iterator where, Buffer&& bb) {
    Write((char*)bb.data(), bb.len, bb.id);
    return where;
}

void QuicRWer::closeHE(RW_EVENT events) {
    if(!(events & RW_EVENT::READ)) {
        return;
    }
    char buff[max_datagram_size];
    while(true) {
        ssize_t ret = read(getFd(), buff, sizeof(buff));
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
        if (ret < 0) {
            LOGE("read error when closing: %s\n", strerror(errno));
            return closeCB();
        }
        walkPackets(buff, ret);
    }
}

void QuicRWer::Close(std::function<void()> func) {
    closeCB = std::move(func);
    walkHandler= [this](const quic_pkt_header* header, std::vector<const quic_frame*>& frames) -> int{
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
    };
    if(getFd() >= 0 && stats == RWerStats::Connected) {
        //we only send CLOSE_CONNECTION_APP frame after handshake now
        //TODO: but it should also be send before handshake
        close_timer = updatejob(close_timer, closeCB, max_idle_timeout);
        handleEvent = (void (Ep::*)(RW_EVENT))&QuicRWer::closeHE;
        setEvents(RW_EVENT::READ);
        // RWER_CLOSING in quic means we have sent or recv CLOSE_CONNECTION_APP frame,
        // so we will not send CLOSE_CONNECTION_APP frame again
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
        addjob(closeCB, 0, JOB_FLAGS_AUTORELEASE);
    }
}

void QuicRWer::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int QuicRWer::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

bool QuicRWer::checkStatelessReset(const void *may_be_token) {
    assert(hisids.size() == 1 || hisids.size() == histoken.size());
    for(auto i = hisid_idx; i < hisids.size(); i++){
        if(histoken[i].empty()){
            continue;
        }
        assert(histoken[i].length() == QUIC_TOKEN_LEN);
        if(memcmp(histoken[i].data(), may_be_token, QUIC_TOKEN_LEN) == 0){
            return true;
        }
    }
    return false;
}

void QuicRWer::walkPackets(const void* buff, size_t length) {
    const char *pos = (const char*)buff;
    while (length > 0) {
        if (*pos == 0) {
            pos++;
            length--;
            continue;
        }
        quic_pkt_header header;
        header.dcid.resize(QUIC_CID_LEN);
        int body_len = unpack_meta(pos, length, &header);
        if (body_len < 0 || body_len > (int)length) {
            LOGE("QUIC meta unpack failed, disacrd it\n");
            return;
        }
        if(ctx == nullptr && header.type == QUIC_PACKET_INITIAL && originDcid.empty()){
            //Init something for server
            originDcid = header.dcid;
            quic_generate_initial_key(0, header.dcid.data(), header.dcid.length(), &contexts[0].write_secret);
            quic_generate_initial_key(1, header.dcid.data(), header.dcid.length(), &contexts[0].read_secret);
            qos.KeyGot(ssl_encryption_initial);
            contexts[0].hasKey = true;
            mgr->rwers.emplace(originDcid, this);

            char quic_params[QUIC_INITIAL_LIMIT];
            SSL_set_quic_transport_params(ssl, (const uint8_t*)quic_params, generateParams(quic_params));
        }
        if (header.dcid != myids[myid_idx] && header.dcid != originDcid) {
            if(checkStatelessReset((char*)buff + body_len - QUIC_TOKEN_LEN)){
                LOGE("QUIC stateless reset with unkwnon dcid\n");
                ErrorHE(PROTOCOL_ERR, QUIC_CONNECTION_REFUSED);
                return;
            }
            LOG("QUIC discard unknown dcid: %s\n",
                dumpHex(header.dcid.data(), header.dcid.length()).c_str());
            return;
        }
        pos += body_len;
        length -= body_len;
        std::vector<const quic_frame*> frames;
        if (header.type != QUIC_PACKET_RETRY) {
            auto context = getContext(header.type);
            if (!context->hasKey) {
                LOG("quic key for level %d is invalid, discard it (%d).\n", context->level, body_len);
                continue;
            }
            header.pn_base = qos.GetLargestPn(context->level) + 1;
            frames = decode_packet(pos - body_len, body_len, &header, &context->read_secret);
            if (frames.empty()) {
                LOGD(DQUIC, "QUIC packet unpack failed, check stateless reset\n");
                if(checkStatelessReset((char*)buff + body_len - QUIC_TOKEN_LEN)){
                    LOGE("QUIC stateless reset\n");
                    ErrorHE(PROTOCOL_ERR, QUIC_CONNECTION_REFUSED);
                    return;
                }
                LOGE("QUIC packet unpack failed, discard it\n");
                return;
            }
        }
        LOGD(DQUIC, "%s -> %s [%" PRIu64"], type: 0x%02x, length: %d\n",
             dumpHex(header.scid.data(), header.scid.length()).c_str(),
             dumpHex(header.dcid.data(), header.dcid.length()).c_str(),
             header.pn, header.type, body_len);
        if(walkHandler(&header, frames)) {
            return;
        }
    }
}

void QuicRWer::reorderData(){
    if(stats == RWerStats::Error){
        return;
    }
    for(auto& context : contexts) {
        if(!context.hasKey){
            continue;
        }
        for (auto i = context.recvq.data.begin(); i != context.recvq.data.end();) {
            FrameResult ret = FrameResult::ok;
            if (context.level != ssl_encryption_application) {
                assert((*i)->type == QUIC_FRAME_CRYPTO);
                ret = handleCryptoFrame(&context, &(*i)->crypto);
            } else {
                ret = handleStreamFrame((*i)->type, &(*i)->stream);
            }
            switch (ret) {
            case FrameResult::ok:
                frame_release(*i);
                i = context.recvq.data.erase(i);
                continue;
            case FrameResult::skip:
                goto theEnd;
            case FrameResult::error:
                return;
            }
        }
theEnd:
        continue;
    }
}

void QuicRWer::ReadData() {
    char buff[max_datagram_size];
    while(true){
        ssize_t ret = read(getFd(), buff, sizeof(buff));
        if (ret < 0 && errno == EAGAIN) {
            break;
        }
        if (ret < 0) {
            ErrorHE(SOCKET_ERR, errno);
            return;
        }
        my_received_data_total += ret;
        walkPackets(buff, ret);
    }
    reorderData();
    // 提供排序好的数据给应用层
    ConsumeRData();
}

void QuicRWer::setResetHandler(std::function<void(uint64_t, uint32_t)> func) {
    resetHandler = func;
}

void QuicRWer::Reset(uint64_t id, uint32_t code) {
    if(streammap.count(id) == 0){
        return;
    }
    auto& status = streammap[id];
    if((status.flags & STREAM_FLAG_FIN_SENT) == 0){
        status.flags |= STREAM_FLAG_FIN_SENT;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_RESET_STREAM;
        frame->reset.id = id;
        frame->reset.error = code;
        frame->reset.fsize = status.my_offset;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    if((status.flags & STREAM_FLAG_STOP_SENT) ==0){
        status.flags |= STREAM_FLAG_STOP_SENT;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_STOP_SENDING;
        frame->stop.id = id;
        frame->stop.error = code;
        qos.PushFrame(ssl_encryption_application, frame);
    }
}

size_t QuicRWer::rlength() {
    return rblen;
}

ssize_t QuicRWer::cap(uint64_t id) {
    if(streammap.count(id) == 0){
        return 0;
    }
    auto& stream = streammap[id];
    if(stream.flags & STREAM_FLAG_FIN_SENT) {
        return 0;
    }
    assert(my_sent_data <= his_max_data);
    assert(wlength() == 0);
    return std::min((long long)stream.his_max_data - (long long)stream.my_offset,
                    (long long)his_max_data - (long long)my_sent_data);
}

bool QuicRWer::idle(uint64_t id){
    if(streammap.count(id) == 0){
        return true;
    }
    //这里收到reset也不认为是idle，因为即使收到reset，也不代表本端不会继续发送数据
    auto& status = streammap[id];
    bool send_closed = false;
    bool recv_closed = false;
    if(status.flags & STREAM_FLAG_FIN_SENT){
        send_closed = true;
    }
    if(status.flags & (STREAM_FLAG_FIN_DELIVED | STREAM_FLAG_RESET_DELIVED)){
        assert(status.flags & STREAM_FLAG_FIN_RECVD);
        assert(status.rb.length() == 0);
        recv_closed = true;
    }
    if((status.flags & STREAM_FLAG_STOP_SENT) && (status.flags & STREAM_FLAG_FIN_RECVD)){
        //这种情况下，stop sending已经发送了，但是因为对方已经发送了fin标记
        //因此不会回复reset包了，而应用层因为已经调用了reset，后续也不会接受fin标记
        //我们就视为fin标记已经被消费了
        recv_closed = true;
    }

    if(IsBidirect(id)){
        return send_closed && recv_closed;
    }
    if(IsLocal(id)){
        return send_closed;
    }
    return recv_closed;
}

void QuicRWer::ConsumeRData() {
    std::list<uint64_t> to_clean;
    for(auto& i: streammap){
        auto& status = i.second;
        if(idle(i.first)){
            to_clean.push_back(i.first);
            continue;
        }
        if(status.flags & (STREAM_FLAG_FIN_DELIVED | STREAM_FLAG_RESET_RECVD)){
            assert((status.flags & STREAM_FLAG_FIN_SENT) == 0);
            continue;
        }
        if((status.flags & STREAM_FLAG_FIN_RECVD) && status.finSize == status.rb.Offset()){
            //如果收到了FIN，即使缓冲区为空，仍需要把FIN发送给应用层
            assert(status.rb.length() == 0);
        }else if(status.rb.length() == 0){
            continue;
        }
        auto& rb = status.rb;
        assert(rblen >= rb.length());
        if(rb.length() > 0){
            auto buff = std::make_shared<Block>(rb.length());
            Buffer wb{buff, rb.get((char*) buff->data(), rb.length()), i.first};
            readCB(wb);
            size_t eaten  = rb.length() - wb.len;
            LOGD(DQUIC, "consume data [%" PRIu64"]: %" PRIu64" - %" PRIu64", left: %zd\n",
                 i.first, rb.Offset(), rb.Offset() + eaten, rb.length() - eaten);
            rb.consume(eaten);
            rblen -= eaten;
        }

        if((status.flags & STREAM_FLAG_FIN_RECVD) && rb.length() == 0){
            assert((status.flags & STREAM_FLAG_FIN_DELIVED) == 0);
            //在QuicRWer中，我们不用 ReadEOF状态，因为它是对整个连接的，而不是对某个stream的
            assert(status.finSize == rb.Offset());
            Buffer ewb{nullptr, i.first};
            readCB(ewb);
            LOGD(DQUIC, "consume EOF [%" PRIu64"]: %" PRIu64"\n", i.first, rb.Offset());
            status.flags |= STREAM_FLAG_FIN_DELIVED;
        }

        auto shouldSendMaxStreamData = [](QuicStreamStatus& status) -> bool {
            if((status.flags & STREAM_FLAG_FIN_RECVD) && status.my_max_data >= status.finSize){
                return false;
            }
            uint64_t offset = status.rb.Offset() + status.rb.length();
            if(status.my_max_data - offset < BUF_LEN/2 && offset + status.rb.cap() > status.my_max_data){
                return true;
            }
            if(offset + status.rb.cap() - status.my_max_data < BUF_LEN){
                return false;
            }
            return true;
        };
        if(shouldSendMaxStreamData(status)){
            status.my_max_data =  rb.Offset() + rb.length() + rb.cap();
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAM_DATA;
            frame->max_stream_data.id = i.first;
            frame->max_stream_data.max = status.my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
        }
        if(idle(i.first)){
            to_clean.push_back(i.first);
        }
    }
    if(my_max_data - my_received_data <= 50 *1024 *1024){
        my_max_data += 50 *1024 *1024;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_MAX_DATA;
        frame->extra = my_max_data;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    for(auto& i: to_clean){
        CleanStream(i);
    }
}

uint64_t QuicRWer::CreateBiStream() {
    uint64_t id = nextLocalBiId;
    nextLocalBiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = my_max_stream_data_bidi_local;
    stat.his_max_data = his_max_stream_data_bidi_remote;
    streammap.emplace(id, std::move(stat));
    return id;
}

uint64_t QuicRWer::CreateUbiStream() {
    uint64_t id = nextLocalUbiId;
    nextLocalUbiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = 0;
    stat.his_max_data = his_max_stream_data_uni;
    streammap.emplace(id, std::move(stat));
    return id;
}

void QuicRWer::disconnect_action() {
    if(flags & RWER_CLOSING){
        return;
    }
    ErrorHE(PROTOCOL_ERR, QUIC_NO_ERROR);
}

void QuicRWer::keepAlive_action() {
    assert(contexts[ssl_encryption_application].hasKey);
    if(flags & RWER_CLOSING){
        return;
    }
    qos.PushFrame(ssl_encryption_application, new quic_frame{QUIC_FRAME_PING, {}});
}

void QuicRWer::dump_status(Dumper dp, void *param) {
    dp(param, "QuicRWer: %s -> %s, read: %zd/%zd, write: %zd/%zd\n my_window: %zd, his_window: %zd rlen: %zd, fullq: %zd\n",
       dumpHex(myids[myid_idx].c_str(), myids[myid_idx].length()).c_str(),
       dumpHex(hisids[hisid_idx].c_str(), myids[myid_idx].length()).c_str(),
       my_received_data, my_received_data_total,
       my_sent_data, my_sent_data_total,
       my_max_data - my_received_data,
       his_max_data - my_sent_data,
       rblen, fullq.size());
    for(auto& status: streammap){
        dp(param, "  0x%lx: rlen: %zd, rcap: %zd, my_window: %zd, his_window: %zd, flags: 0x%08x\n",
           status.first, status.second.rb.length(), status.second.rb.cap(),
           status.second.my_max_data - status.second.his_offset,
           status.second.his_max_data - status.second.my_offset,
           status.second.flags);
    }
}
