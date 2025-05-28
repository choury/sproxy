//
// Created by 周威 on 2021/6/20.
//
#include "quicio.h"
#include "quic_server.h"
#include "quic_pack.h"
#include "misc/net.h"
#include "misc/defer.h"
#include "prot/tls.h"
#include "prot/multimsg.h"
#include <openssl/err.h>
#include <unistd.h>
#include <assert.h>
#include <inttypes.h>

#include <algorithm>
#include <random>

#if __ANDROID__
extern std::string getExternalFilesDir();
#endif

/*TODO:
 * 连接迁移
 * 多地址，失败轮询重试
 * check retry packet tag
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

void QuicBase::dropkey(OSSL_ENCRYPTION_LEVEL level) {
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

QuicBase::quic_context* QuicBase::getContext(uint8_t type) {
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

int QuicBase::set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                     const uint8_t *read_secret,
                                     const uint8_t *write_secret, size_t secret_len) {
    uint32_t cipher = SSL_CIPHER_get_id(SSL_get_current_cipher(ssl));
    LOGD(DQUIC, "set_secret: level %d, len: %zd, cipher: 0x%X\n",
         level, secret_len, cipher);
    QuicBase* rwer = (QuicBase *)SSL_get_app_data(ssl);
    // assert(secret_len <= 32);
    if (quic_secret_set_key(&rwer->contexts[level].read_secret, (const char *)read_secret, cipher) < 0 ||
        quic_secret_set_key(&rwer->contexts[level].write_secret, (const char *)write_secret, cipher) < 0)
    {
        return 0;
    }
    rwer->qos.KeyGot(level);
    rwer->contexts[level].hasKey = true;
    if(rwer->ctx) {
        //drop init key if client mode
        rwer->dropkey(ssl_encryption_initial);
    }
    return 1;
}

int QuicBase::set_read_secret(SSL* ssl,
                              enum ssl_encryption_level_t level,
                              const SSL_CIPHER* cp,
                              const uint8_t* secret, size_t secret_len) {
    uint32_t cipher = SSL_CIPHER_get_id(cp);
    LOGD(DQUIC, "set_read_secret: level %d, len: %zd, cipher: 0x%X\n",
         level, secret_len, cipher);
    QuicBase* rwer = (QuicBase*)SSL_get_app_data(ssl);
    if(quic_secret_set_key(&rwer->contexts[level].read_secret, (const char*)secret, cipher) < 0) {
        return 0;
    }
    rwer->qos.KeyGot(level);
    rwer->contexts[level].hasKey = true;
    if(rwer->ctx) {
        //drop init key if client mode
        rwer->dropkey(ssl_encryption_initial);
    }
    return 1;
}

int QuicBase::set_write_secret(SSL* ssl,
                               enum ssl_encryption_level_t level,
                               const SSL_CIPHER* cp,
                               const uint8_t* secret, size_t secret_len) {
    uint32_t cipher = SSL_CIPHER_get_id(cp);
    LOGD(DQUIC, "set_write_secret: level %d, len: %zd, cipher: 0x%X\n",
         level, secret_len, cipher);
    QuicBase* rwer = (QuicBase*)SSL_get_app_data(ssl);
    if(quic_secret_set_key(&rwer->contexts[level].write_secret, (const char*)secret, cipher) < 0) {
        return 0;
    }
    //we set hasKey on read_secret
    return 1;
}



size_t QuicBase::envelopLen(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, size_t len){
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

size_t QuicBase::envelop(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, const char* in, size_t len, void* out) {
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

    size_t packet_len = encode_packet(in, len, &header, secret, (char*)out);
    if(packet_len == 0){
        return 0;
    }
    if(header.type == QUIC_PACKET_INITIAL && packet_len < QUIC_INITIAL_LIMIT && ctx){
        memset((char*)out + packet_len, 0, QUIC_INITIAL_LIMIT - packet_len);
        packet_len = QUIC_INITIAL_LIMIT;
    }
    if(header.type == QUIC_PACKET_1RTT){
        LOGD(DQUIC, " <- %s [%" PRIu64"], type: 0x%02x, length: %d\n",
             dumpHex(header.scid.data(), header.scid.length()).c_str(),
             header.pn, header.type, (int) packet_len);
    }else {
        LOGD(DQUIC, "%s <- %s [%" PRIu64"], type: 0x%02x, length: %d\n",
             dumpHex(header.dcid.data(), header.dcid.length()).c_str(),
             dumpHex(header.scid.data(), header.scid.length()).c_str(),
             header.pn, header.type, (int) packet_len);
    }
    return packet_len;
}


std::list<quic_packet_pn> QuicBase::send(OSSL_ENCRYPTION_LEVEL level,
                                         uint64_t pn, uint64_t ack,
                                         std::list<quic_frame*>& pend_frames, size_t window)
{
    size_t envLen = envelopLen(level, pn, ack, std::min((size_t)his_max_payload_size, window));
    assert(window > envLen);

    size_t bufleft = getWritableSize();
    if(his_max_payload_size > bufleft){
        LOGD(DQUIC, "bufleft is too small: %zd vs %zd\n", bufleft, (size_t)his_max_payload_size);
        return {};
    }
    size_t max_iov = std::min((size_t)100, bufleft/(size_t)his_max_payload_size);
    std::list<quic_packet_pn> sent_packets;
    sent_packets.emplace_back(quic_packet_pn{{pn++, envLen}, {}});
    do {
        auto& packet = sent_packets.back();
        quic_frame* frame = pend_frames.front();
        uint64_t type = frame->type;
        ssize_t left = std::min((size_t)his_max_payload_size,  window) - packet.meta.sent_bytes;
        if(left < (int)pack_frame_len(frame)){
            if (type == QUIC_FRAME_CRYPTO && left >= 20){
                // [off, off+len) -> [off, off + left - 20) + [off + left - 20, off+len)
                quic_frame* fframe = new quic_frame{type, {}};
                fframe->crypto.offset = frame->crypto.offset + left - 20;
                fframe->crypto.length = frame->crypto.length - left + 20;
                fframe->crypto.buffer = new Buffer(*frame->crypto.buffer);
                fframe->crypto.buffer->reserve(left - 20);
                pend_frames.insert(std::next(pend_frames.begin()), fframe);
                frame->crypto.length = left - 20;
            } else if ((type >= QUIC_FRAME_STREAM_START_ID && type <= QUIC_FRAME_STREAM_END_ID) && left >= 30) {
                // [off, off+len) -> [off, off + left - 30) + [off + left - 30, off+len)
                quic_frame *fframe = new quic_frame{type | QUIC_FRAME_STREAM_OFF_F, {}};
                fframe->stream.id = frame->stream.id;
                fframe->stream.offset = frame->stream.offset + left - 30;
                fframe->stream.length = frame->stream.length - left + 30;
                fframe->stream.buffer = new Buffer(*frame->stream.buffer);
                fframe->stream.buffer->reserve(left - 30);
                pend_frames.insert(std::next(pend_frames.begin()), fframe);
                frame->stream.length = left - 30;
                frame->type &= ~QUIC_FRAME_STREAM_FIN_F;
            }else if(window < his_max_payload_size/2) {
                break;
            } else {
                assert(!packet.frames.empty());
                window -= packet.meta.sent_bytes;
                sent_packets.emplace_back(quic_packet_pn{{pn++, envLen}, {}});
                continue;
            }
        }
        if (type >= QUIC_FRAME_STREAM_START_ID && type <= QUIC_FRAME_STREAM_END_ID) {
            packet.meta.streamIds.emplace(frame->stream.id);
        }
        packet.meta.ack_eliciting |=  is_ack_eliciting(frame);
        packet.meta.in_flight |=  packet.meta.ack_eliciting || frame->type == QUIC_FRAME_PADDING;
        packet.meta.sent_bytes += pack_frame_len(frame);
        packet.frames.push_back(frame);
        pend_frames.pop_front();
        assert(packet.meta.sent_bytes <= (size_t)his_max_payload_size);
    }while(!pend_frames.empty() && sent_packets.size() < max_iov);
    Block blk(sent_packets.size() * his_max_payload_size);
    char* start = (char*)blk.data();
    std::vector<iovec> iov;
    for(auto& packet: sent_packets) {
        if(packet.frames.empty()) {
            assert(packet.meta.pn == sent_packets.back().meta.pn);
            sent_packets.pop_back();
            break;
        }
        char buffer[his_max_payload_size];
        char* pos = buffer;
        for(const auto& frame : packet.frames) {
            pos = (char*)pack_frame(pos, frame);
            if(pos == nullptr){
                LOGE("QUIC failed to pack frame");
                return {};
            }
        }
        size_t packet_len = envelop(level, packet.meta.pn, ack, buffer, pos - buffer, start);
        if(packet_len == 0){
            LOGE("QUIC failed to pack packet");
            return {};
        }
        packet.meta.sent_time = getutime();
        //这里sent_bytes 是有可能和packet_len 不同的，因为envLen是按照max_datagram_len作为长度预估的，可能会更大
        packet.meta.sent_bytes = packet_len;
        assert(packet_len == packet.meta.sent_bytes);
        iov.push_back({start, packet_len});
        start += packet_len;
    }

    int ret = writem(iov.data(), iov.size());
    if (ret < 0) {
        LOGE("QUIC writem failed: %s\n", strerror(errno));
        return {};
    }
    size_t sentlen = start - (char*)blk.data();
    if((size_t)ret < iov.size()) {
        LOGE("sent packet: %d/%zd, sent size: %zd buffer: %zd/%zd\n", ret, iov.size(), sentlen,
             getWritableSize(), bufleft);
    } else {
        LOGD(DQUIC, "sent packet: %d/%zd, sent size: %zd buffer: %zd\n", ret, iov.size(), sentlen, bufleft);
    }
    my_sent_data_total += sentlen;
    return sent_packets;
}

int QuicBase::add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                 const uint8_t *data, size_t len) {
    QuicBase* rwer = (QuicBase*)SSL_get_app_data(ssl);
    quic_context* context = &rwer->contexts[level];

    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_CRYPTO;
    frame->crypto.buffer = new Buffer(len);
    memcpy(frame->crypto.buffer->mutable_data(), data, len);
    frame->crypto.offset = context->crypto_offset;
    frame->crypto.length = len;
    frame->crypto.buffer->truncate(len);
    rwer->qos.PushFrame(level, frame);
    context->crypto_offset += len;
    return 1;
}

int QuicBase::flush_flight(SSL *ssl){
    QuicBase* rwer = (QuicBase*)SSL_get_app_data(ssl);
    rwer->qos.sendPacket();
    return 1;
}

int QuicBase::send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert){
    QuicBase* rwer = (QuicBase*)SSL_get_app_data(ssl);
    if(rwer->isClosing){
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
    rwer->qos.sendPacket();
    rwer->onError(PROTOCOL_ERR, QUIC_CRYPTO_ERROR);
    return 1;
}

static SSL_QUIC_METHOD quic_method{
#ifdef USE_BORINGSSL
    QuicBase::set_read_secret,
    QuicBase::set_write_secret,
#else
    QuicBase::set_encryption_secrets,
#endif
    QuicBase::add_handshake_data,
    QuicBase::flush_flight,
    QuicBase::send_alert,
};

void QuicBase::generateCid() {
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dis(0x1000000000, 0xFFFFFFFFFF);
    std::string hisid, myid;
    myid.resize(QUIC_CID_LEN + 1);
    snprintf(&myid[0], myid.size(), "sproxy0000%010" PRIx64, dis(rng));
    set32(&myid[6], getutime());
    myid.resize(QUIC_CID_LEN);

    hisid.resize(QUIC_CID_LEN + 1);
    snprintf(&hisid[0], hisid.size(), "sproxy0000%010" PRIx64, dis(rng));
    set32(&hisid[6], getutime());
    hisid.resize(QUIC_CID_LEN);

    myids.push_back(myid);
    hisids.push_back(hisid);
    histoken.emplace_back("");

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

size_t QuicBase::generateParams(char data[QUIC_INITIAL_LIMIT]) {
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

void QuicBase::getParams(const uint8_t* data, size_t len) {
    const uint8_t* pos = data;
    while(pos - data < (int)len){
        uint64_t name, size, value;
        pos += variable_decode(pos, &name);
        pos += variable_decode(pos, &size);
        switch(name){
        case quic_original_destination_connection_id:
            LOGD(DQUIC, "get original dcid: %s\n", dumpHex(pos, size).c_str());
            break;
        case quic_max_idle_timeout:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max idle timeout: %" PRIu64"\n", value);
            if(value < max_idle_timeout && value > 0){
                max_idle_timeout = value;
            }
            break;
        case quic_stateless_reset_token:
            if(size == QUIC_TOKEN_LEN) {
                LOGD(DQUIC, "get token: %s\n", dumpHex(pos, size).c_str());
                histoken[0] = std::string((char*)pos, QUIC_TOKEN_LEN);
            }else{
                LOGE("ignore malformed stateless reset token: %zd\n", (size_t)size);
            }
            break;
        case quic_max_udp_payload_size:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max payload size: %" PRIu64"\n", value);
            if(value > 1200){
                his_max_payload_size = value;
            }
            break;
        case quic_initial_max_data:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max data: %" PRIu64"\n", value);
            if(value > his_max_data){
                his_max_data = value;
            }
            break;
        case quic_initial_max_stream_data_bidi_local:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max stream data bidi local: %" PRIu64"\n", value);
            if(value > his_max_stream_data_bidi_local){
                his_max_stream_data_bidi_local = value;
            }
            break;
        case quic_initial_max_stream_data_bidi_remote:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max stream data bidi remote: %" PRIu64"\n", value);
            if(value > his_max_stream_data_bidi_remote){
                his_max_stream_data_bidi_remote = value;
            }
            break;
        case quic_initial_max_stream_data_uni:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max stream data uni: %" PRIu64"\n", value);
            if(value > his_max_stream_data_uni){
                his_max_stream_data_uni = value;
            }
            break;
        case quic_initial_max_streams_bidi:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max streams bidi: %" PRIu64"\n", value);
            if(value > his_max_streams_bidi) {
                his_max_streams_bidi = value;
            }
            break;
        case quic_initial_max_streams_uni:
            variable_decode(pos, &value);
            LOGD(DQUIC, "get max streams uni: %" PRIu64"\n", value);
            if(value > his_max_streams_uni) {
                his_max_streams_uni = value;
            }
            break;
        case quic_ack_delay_exponent:{
            uint64_t ack_delay_exponent;
            variable_decode(pos, &ack_delay_exponent);
            LOGD(DQUIC, "get ack delay exponent: %" PRIu64"\n", ack_delay_exponent);
            qos.SetAckDelayExponent(ack_delay_exponent);
            break;
        }
        case quic_max_ack_delay:
            variable_decode(pos, &his_max_ack_delay);
            LOGD(DQUIC, "get max ack delay: %" PRIu64"\n", his_max_ack_delay);
            break;
        case quic_version_information:{
            chosen_version = get32(pos);
            LOGD(DQUIC, "chosen version: %x\n", chosen_version);
            size -= 4;
            pos  += 4;
            while(size) {
                uint32_t ver = get32(pos);
                LOGD(DQUIC, "available version: %x\n", ver);
                size -= 4;
                pos  += 4;
            }
            break;
        }
        case quic_disable_active_migration:
        case quic_preferred_address:
        case quic_active_connection_id_limit:
        case quic_initial_source_connection_id:
        case quic_retry_source_connection_id:
        case quic_max_datagram_frame_size:
        case quic_grease_quic_bit:
            LOG("unimplemented quic param: %" PRIu64"\n", name);
            break;
        default:
            if((name - 27) % 31 != 0) {
                LOG("unknown quic param: %" PRIu64"\n", name);
            }
            break;
        }
        pos += size;
    }
}

QuicBase::QuicBase(const char* hostname):
        qos(false,
            [this] (auto&& v1, auto&& v2, auto&& v3, auto&& v4, auto&& v5) {
                return this->send(v1, v2, v3, v4, v5);
            },
            [this] (auto&& v1, auto&& v2) {
                resendFrames(v1, v2);
            })
{
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) {
        LOGF("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_write_line);

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if(SSL_CTX_set_ciphersuites(ctx, QUIC_CIPHERS) != 1) {
        LOGF("SSL_CTX_set_ciphersuites: %s [%s]\n", ERR_error_string(ERR_get_error(), nullptr), QUIC_CIPHERS);
    }

    if(SSL_CTX_set1_groups_list(ctx, QUIC_GROUPS) != 1) {
        LOGF("SSL_CTX_set1_groups_list failed\n");
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
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);

    generateCid();
    nextLocalBiId   = 0;
    nextRemoteBiId  = 1;
    nextLocalUbiId  = 2;
    nextRemoteUbiId = 3;
    walkHandler = [this](auto&& v1, auto&& v2) { return handlePacket(v1, v2); };
}

QuicBase::QuicBase(SSL_CTX *ctx):
        qos(true,
            [this](auto&& v1, auto&& v2, auto&& v3, auto&& v4, auto&& v5){
                return this->send(v1, v2, v3, v4, v5);
            },
            [this] (auto&& v1, auto&& v2) {
                resendFrames(v1, v2);
            })
{
    ssl = SSL_new(ctx);
    SSL_set_quic_method(ssl, &quic_method);
    if(ssl == nullptr){
        LOGF("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_set_app_data(ssl, this);
    SSL_set_accept_state(ssl);
    sslStats = SslStats::SslAccepting;

    generateCid();
    nextRemoteBiId  = 0;
    nextLocalBiId   = 1;
    nextRemoteUbiId = 2;
    nextLocalUbiId  = 3;
    walkHandler = [this](auto&& v1, auto&& v2) { return handlePacket(v1, v2);};
}

QuicBase::~QuicBase(){
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
}

int QuicBase::doSslConnect(const char* hostname) {
    sslStats = SslStats::SslConnecting;
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
        LOGE("(%s): quic connect error:%s\n", hostname, strerror(error));
        onError(SSL_SHAKEHAND_ERR, error);
        return -1;
    }
    return 0;
}

QuicBase::FrameResult QuicBase::handleCryptoFrame(quic_context* context, const quic_crypto* crypto){
    if(crypto->offset + crypto->length <= context->crypto_want) {
        LOGD(DQUIC, "ignore dup crypto frame [%zd]\n", context->crypto_want);
        return FrameResult::ok;
    }
    if(crypto->offset > context->crypto_want) {
        LOGD(DQUIC, "skip unwanted crypto frame [%zd/%" PRIu64"]\n", context->crypto_want, crypto->offset);
        return FrameResult::skip;
    }
    const uint8_t* start = (const uint8_t*)crypto->buffer->data() + (context->crypto_want - crypto->offset);
    size_t len = crypto->offset + crypto->length - context->crypto_want;
    SSL_provide_quic_data(ssl, context->level, start, len);
    context->crypto_want = crypto->offset + crypto->length;
    if(context->level == ssl_encryption_application){
        if(ssl_get_error(ssl, SSL_process_quic_post_handshake(ssl)) != 1){
            int error = errno;
            LOGE("(%s): quic process post handshake error:%s\n",
                 dumpHex(hisids[hisid_idx].data(), hisids[hisid_idx].length()).c_str(), strerror(error));
            onError(PROTOCOL_ERR, error);
            return FrameResult::error;
        }
    }else {
        size_t olen = 0;
        const uint8_t* buff = nullptr;
        if(!hasParam && (SSL_get_peer_quic_transport_params(ssl, &buff, &olen), olen > 0)){
            getParams(buff, olen);
            if(chosen_version != QUIC_VERSION_1) {
                return FrameResult::error;
            }
            hasParam = true;
        }
        if(ssl_get_error(ssl, SSL_do_handshake(ssl)) == 1){
            LOGD(DQUIC, "SSL_do_handshake succeed\n");
            his_max_ack_delay = his_max_ack_delay?:25;
            qos.SetMaxAckDelay(his_max_ack_delay);
            if(ctx == nullptr){
                //send handshake done frame to client
                qos.PushFrame(ssl_encryption_application, new quic_frame{QUIC_FRAME_HANDSHAKE_DONE, {}});
                dropkey(ssl_encryption_handshake);
            }else{
                //discard token from retry packet.
                initToken.clear();
            }
            sslStats = SslStats::Established;
            onConnected();
        }else if(errno != EAGAIN){
            int error = errno;
            LOGE("(%s): ssl connect error:%s\n",
                    dumpHex(hisids[hisid_idx].data(), hisids[hisid_idx].length()).c_str(), strerror(error));
            onError(SSL_SHAKEHAND_ERR, error);
            return FrameResult::error;
        }
    }
    return FrameResult::ok;
}

bool QuicBase::isLocal(uint64_t id) {
    return (ctx == nullptr) == ((id&0x01) == 0x01);
}

bool QuicBase::isBidirect(uint64_t id) {
    return (id&0x02) == 0;
}

QuicBase::iterator QuicBase::openStream(uint64_t id) {
    if(streammap.count(id)){
        return streammap.find(id);
    }
    if(isBidirect(id)){
        // Bidirectional
        if(isLocal(id)){
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
        if(isLocal(id)){
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

void QuicBase::cleanStream(uint64_t id) {
    assert(idle(id));
    LOGD(DQUIC, "clean idle stream: %" PRIu64"\n", id);
    for(auto i = fullq.begin(); i != fullq.end(); ){
        if((*i)->stream.id != id) {
            i++;
            continue;
        }
        LOGD(DQUIC, "discard data: %" PRIu64" - %" PRIu64"\n",
             (*i)->stream.offset, (*i)->stream.offset + (*i)->stream.length);
        frame_release(*i);
        i = fullq.erase(i);
    }
    if(streammap.count(id)){
        streammap.erase(id);
    }
}


QuicBase::FrameResult QuicBase::handleStreamFrame(uint64_t type, const quic_stream *stream) {
    auto id = stream->id;
    if(isBidirect(id) ? id > my_max_streams_bidi : id > my_max_streams_uni) {
        onError(PROTOCOL_ERR, QUIC_STREAM_LIMIT_ERROR);
        qos.PushFrame(ssl_encryption_application, new quic_frame{
            .type = QUIC_FRAME_CONNECTION_CLOSE,
            .close = {
                .error = QUIC_STREAM_LIMIT_ERROR,
                .frame_type = type,
                .reason_len = 0,
                .reason = nullptr,
            }
        });
        return FrameResult::error;
    }
    auto itr = openStream(id);
    if(itr == streammap.end()){
        //it is a retransmissions pkg
        return FrameResult::ok;
    }
    if (isBidirect(id)) {
        my_received_max_bidistream_id = std::max(my_received_max_bidistream_id, id);
    } else {
        my_received_max_unistream_id = std::max(my_received_max_unistream_id, id);
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
            onError(PROTOCOL_ERR, QUIC_FINAL_SIZE_ERROR);
            qos.PushFrame(ssl_encryption_application, new quic_frame{
                .type = QUIC_FRAME_CONNECTION_CLOSE,
                .close = {
                    .error = QUIC_FINAL_SIZE_ERROR,
                    .frame_type = type,
                    .reason_len = 0,
                    .reason = nullptr,
                }
            });
            return FrameResult::error;
        }
    }
    uint64_t his_offset = stream->offset + stream->length;
    if(his_offset > status.my_max_data) {
        onError(PROTOCOL_ERR, QUIC_FLOW_CONTROL_ERROR);
        qos.PushFrame(ssl_encryption_application, new quic_frame{
            .type = QUIC_FRAME_CONNECTION_CLOSE,
            .close = {
                .error = QUIC_FLOW_CONTROL_ERROR,
                .frame_type = type,
                .reason_len = 0,
                .reason = nullptr,
            }
        });
        return FrameResult::error;
    }
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
    const char* start = (const char*)stream->buffer->data() + (want - stream->offset);
    size_t len = stream->length + stream->offset - want;
    if(status.rb.put(start, len) < 0){
        onError(PROTOCOL_ERR, QUIC_FLOW_CONTROL_ERROR);
        qos.PushFrame(ssl_encryption_application, new quic_frame{
            .type = QUIC_FRAME_CONNECTION_CLOSE,
            .close = {
                .error = QUIC_FLOW_CONTROL_ERROR,
                .frame_type = type,
                .reason_len = 0,
                .reason = nullptr,
            }
        });
        return FrameResult::error;
    }
    want += len;
    rblen += len;
    my_received_data += len;
    LOGD(DQUIC, "received data [%" PRIu64"] <%" PRIu64"/%" PRIu64"> <%" PRIu64"/%" PRIu64">%s\n",
         id, want, status.my_max_data, my_received_data, my_max_data,
         (type & QUIC_FRAME_STREAM_FIN_F)?" EOF":"");

    //这里不调用consume的原因是我们希望把数据合并后一起上送，减少调用次数
    return FrameResult::ok;
}

QuicBase::FrameResult QuicBase::handleResetFrame(const quic_reset *stream) {
    auto id = stream->id;
    auto itr = openStream(id);
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
        onError(PROTOCOL_ERR, QUIC_FINAL_SIZE_ERROR);
        qos.PushFrame(ssl_encryption_application, new quic_frame{
            .type = QUIC_FRAME_CONNECTION_CLOSE,
            .close = {
                .error = QUIC_FINAL_SIZE_ERROR,
                .frame_type = QUIC_FRAME_RESET_STREAM,
                .reason_len = 0,
                .reason = nullptr,
            }
        });
        return FrameResult::error;
    }

    status.flags |= STREAM_FLAG_FIN_RECVD | STREAM_FLAG_RESET_RECVD;
    status.finSize = stream->fsize;
    my_received_data += status.finSize - want;

    if((status.flags & STREAM_FLAG_RESET_DELIVED) == 0) {
        LOGD(DQUIC, "reset stream for %" PRIu64"\n", id);
        resetHandler(id, stream->error);
        status.flags |= STREAM_FLAG_RESET_DELIVED;
        status.rb.consume(status.rb.length());
    }
    return FrameResult::ok;
}

QuicBase::FrameResult QuicBase::handleHandshakeFrames(quic_context *context, const quic_frame *frame) {
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
        qos.DrainAll();
        isClosing = true;
        onError(SSL_SHAKEHAND_ERR, (int) frame->close.error);
        return FrameResult::error;
    default:
        onError(SSL_SHAKEHAND_ERR, QUIC_PROTOCOL_VIOLATION);
        qos.PushFrame(context->level, new quic_frame{
            .type = QUIC_FRAME_CONNECTION_CLOSE,
            .close = {
                .error = QUIC_PROTOCOL_VIOLATION,
                .frame_type = 0,
                .reason_len = 0,
                .reason = nullptr,
            }
        });
        return FrameResult::error;
    }
}

int QuicBase::handleHandshakePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
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

int QuicBase::handleRetryPacket(const quic_pkt_header* header){
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
    return 0;
}

QuicBase::FrameResult QuicBase::handleFrames(quic_context *context, const quic_frame *frame) {
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
        if(frame->extra <= his_max_data) {
            return FrameResult::ok;
        }
        his_max_data = frame->extra;
        for(const auto& [id, stream]: streammap){
            if(!canSend(id) || stream.his_max_data < stream.my_offset + my_max_payload_size) {
                continue;
            }
            onWrite(id);
        }
        return FrameResult::ok;
    case QUIC_FRAME_DATA_BLOCKED: {
        auto recv_max_data = frame->extra;
        if(recv_max_data - my_received_data <= 50 *1024 *1024){
            my_max_data = my_received_data + 50 *1024 *1024;
            quic_frame* frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_DATA;
            frame->extra = my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
        } else {
            LOGD(DQUIC, "No space to expand data size: %zd vs %zd %zd\n",
                 (size_t)recv_max_data, (size_t)my_max_data, (size_t)my_received_data);
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_STREAMS_BLOCKED_BI: {
        auto recv_max_streams_bidi = frame->extra;
        if (recv_max_streams_bidi - my_received_max_bidistream_id / 4 <= 100) {
            my_max_streams_bidi = my_received_max_bidistream_id/ 4  + 100;
            quic_frame *frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAMS_BI;
            frame->extra = my_max_streams_bidi;
            qos.PushFrame(ssl_encryption_application, frame);
        } else {
            LOGD(DQUIC, "No space to expand bidi-streams: %zd vs %zd %zd\n",
                 (size_t)recv_max_streams_bidi, (size_t)my_max_streams_bidi, (size_t)my_received_max_bidistream_id/4);
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_STREAMS_BLOCKED_UBI: {
        auto recv_max_streams_uni = frame->extra;
        if (recv_max_streams_uni - my_received_max_unistream_id / 4 <= 100) {
            my_max_streams_uni += my_received_max_unistream_id/4 + 100;
            quic_frame *frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAMS_UBI;
            frame->extra = my_max_streams_uni;
            qos.PushFrame(ssl_encryption_application, frame);
        } else {
            LOGD(DQUIC, "No space to expand uni-streams: %zd vs %zd %zd\n",
                 (size_t)recv_max_streams_uni, (size_t)my_max_streams_uni, (size_t)my_received_max_unistream_id/4);
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
        auto itr = openStream(frame->stop.id);
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
            resetHandler(frame->stop.id, frame->stop.error);
            status.rb.consume(status.rb.length());
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_MAX_STREAM_DATA: {
        auto itr = openStream(frame->max_stream_data.id);
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
            if((*i)->type & QUIC_FRAME_STREAM_FIN_F) {
                status.flags |= STREAM_FLAG_FIN_SENT;
            }
            i = fullq.erase(i);
        }
        status.his_max_data = new_max_data;
        if(new_max_data >= status.my_offset) {
            //这里如果max_data大于offset的话，那么fullq里面就应该不存在这个流的包了
            if(idle(itr->first)){
                cleanStream(itr->first);
            }else{
                onWrite(itr->first);
            }
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_STREAM_DATA_BLOCKED:{
        auto itr = openStream(frame->stream_data_blocked.id);
        if (itr == streammap.end()) {
            LOGD(DQUIC, "ignore not opened stream data\n");
            return FrameResult::ok;
        }
        auto &rb = itr->second.rb;
        auto my_max_data = rb.Offset() + rb.length() + rb.cap();
        auto recv_max_data = frame->max_stream_data.max;
        if(my_max_data > recv_max_data) {
            itr->second.my_max_data = my_max_data;
            quic_frame *frame = new quic_frame;
            frame->type = QUIC_FRAME_MAX_STREAM_DATA;
            frame->max_stream_data.id = itr->first;
            frame->max_stream_data.max = my_max_data;
            qos.PushFrame(ssl_encryption_application, frame);
        } else {
            LOGD(DQUIC, "No space to expand stream [%d]: %zd vs %zd vs %zd\n", (int)frame->max_stream_data.id,
                 (size_t)recv_max_data, (size_t)my_max_data, (size_t)itr->second.my_max_data);
        }
        return FrameResult::ok;
    }
    case QUIC_FRAME_RESET_STREAM:
        return handleResetFrame(&frame->reset);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        qos.DrainAll();
        isClosing = true;
        onError(PROTOCOL_ERR, (int) frame->close.error);
        return FrameResult::error;
    case QUIC_FRAME_NEW_TOKEN:
        if(ctx == nullptr){
            LOGE("Get new token from client\n");
            onError(PROTOCOL_ERR, QUIC_PROTOCOL_VIOLATION);
            return FrameResult::error;
        }else {
            initToken = frame->new_token.token;
            return FrameResult::ok;
        }
    case QUIC_FRAME_NEW_CONNECTION_ID:
        if(frame->new_id.retired > frame->new_id.seq){
            onError(PROTOCOL_ERR, QUIC_FRAME_ENCODING_ERROR);
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
            onError(PROTOCOL_ERR, QUIC_PROTOCOL_VIOLATION);
            return FrameResult::error;
        }
        onCidChange(myids[frame->extra], true);
        return FrameResult::ok;
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            return handleStreamFrame(frame->type, &frame->stream);
        } else {
            LOG("ignore unknow quic frame type: 0x%lx\n", (long)frame->type);
        }
        return FrameResult::ok;
    }
}

void QuicBase::notifyBlocked(uint64_t id) {
    if(my_sent_data + 10 * my_max_payload_size >= his_max_data) {
        quic_frame* block = new quic_frame{QUIC_FRAME_MAX_DATA, {}};
        block->extra = his_max_data;
        qos.PushFrame(ssl_encryption_application, block);
    }
    if(!canSend(id)) {
        return;
    }

    const auto& stream = streammap[id];
    if(stream.my_offset + my_max_payload_size >= stream.his_max_data) {
        quic_frame* block = new quic_frame{QUIC_FRAME_STREAM_DATA_BLOCKED, {}};
        block->stream_data_blocked.id = id;
        block->stream_data_blocked.size = stream.his_max_data;
        qos.PushFrame(ssl_encryption_application, block);
    }
}

void QuicBase::resendFrames(pn_namespace* ns, quic_frame *frame) {
    if(isClosing) {
        frame_release(frame);
        return;
    }
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
        auto& stream = streammap[id];
        stream.my_max_data =  stream.rb.Offset() + stream.rb.length() + stream.rb.cap();
        frame->max_stream_data.max = stream.my_max_data;
        qos.FrontFrame(ns, frame);
        break;
    }
    case QUIC_FRAME_MAX_STREAMS_BI: {
        frame->extra = my_max_streams_bidi;
        qos.FrontFrame(ns, frame);
        break;
    }
    case QUIC_FRAME_MAX_STREAMS_UBI: {
        frame->extra = my_max_streams_uni;
        qos.FrontFrame(ns, frame);
        break;
    }
    case QUIC_FRAME_DATA_BLOCKED:
        notifyBlocked(0);
        frame_release(frame);
        break;
    case QUIC_FRAME_STREAM_DATA_BLOCKED:{
        uint64_t id = frame->stream_data_blocked.id;
        notifyBlocked(id);
        frame_release(frame);
        break;
    }
    default:
        if(frame->type >= QUIC_FRAME_STREAM_START_ID && frame->type <= QUIC_FRAME_STREAM_END_ID){
            while(frame->stream.length > his_max_payload_size){
                quic_frame* fframe = new quic_frame{
                    QUIC_FRAME_STREAM_START_ID | QUIC_FRAME_STREAM_OFF_F | QUIC_FRAME_STREAM_LEN_F,
                    {}
                };
                fframe->stream.id =  frame->stream.id;
                fframe->stream.offset = frame->stream.offset;
                fframe->stream.length = his_max_payload_size;
                fframe->stream.buffer = new Buffer(*frame->stream.buffer);
                qos.FrontFrame(ns, fframe);
                frame->stream.offset += his_max_payload_size;
                frame->stream.length -= his_max_payload_size;
                frame->stream.buffer->reserve((int)his_max_payload_size);
            }
            qos.PushFrame(ns, frame);
        }else {
            //FIXME: implement other frame type resend logic
            qos.PushFrame(ns, frame);
        }
    }
}

int QuicBase::handle1RttPacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    auto context = &contexts[ssl_encryption_application];
    keepAlive_timer = UpdateJob(std::move(keepAlive_timer),
                                [this]{keepAlive_action();},
                                std::min(30000, (int)max_idle_timeout/2));
    for(auto frame : frames) {
        auto acked = qos.handleFrame(context->level, header->pn, frame);
        for(auto& id: acked) {
            if(!canSend(id)) {
                continue;
            }
            onWrite(id);
        }
        switch(handleFrames(context, frame)){
        case FrameResult::ok:
            frame_release(frame);
            break;
        case FrameResult::skip:
            //有丢包，立即发送ack
            qos.sendPacket();
            context->recvq.insert(frame);
            break;
        case FrameResult::error:
            frame_release(frame);
            return 1;
        }
    }
    return 0;
}

int QuicBase::handlePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames) {
    disconnect_timer = UpdateJob(std::move(disconnect_timer),
                                 [this]{disconnect_action();}, max_idle_timeout);
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

void QuicBase::sendData(Buffer&& bb) {
    if(isClosing) {
        LOGD(DQUIC, "drop data after close: %d, len:%zd\n", (int)bb.id, bb.len);
        return;
    }
    uint64_t id = bb.id;
    size_t len = bb.len;
    assert(streammap.count(id));

    auto& stream = streammap[id];
    assert((stream.flags & STREAM_FLAG_FIN_SENT) == 0);
    quic_frame* frame = new quic_frame;
    frame->type = QUIC_FRAME_STREAM_START_ID | QUIC_FRAME_STREAM_LEN_F;
    if(stream.my_offset) {
        frame->type |= QUIC_FRAME_STREAM_OFF_F;
    }
    if(len == 0){
        frame->type |= QUIC_FRAME_STREAM_FIN_F;
    }
    frame->stream.id = id;
    frame->stream.length = len;
    frame->stream.offset =  stream.my_offset;
    frame->stream.buffer =  new Buffer(std::move(bb));
    if(len > 0) {
        stream.my_offset += len;
        my_sent_data += len;
        assert(my_sent_data <= his_max_data);
    }
    notifyBlocked(id);
    if(stream.my_offset > stream.his_max_data) {
        fullq.push_back(frame);
        LOGD(DQUIC, "push data [%" PRIu64"] to fullq: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
             id, stream.my_offset, stream.his_max_data, my_sent_data, his_max_data);
        return;
    }
    qos.PushFrame(ssl_encryption_application, frame);
    if(len == 0) {
        stream.flags |= STREAM_FLAG_FIN_SENT;
    }
    LOGD(DQUIC, "send data [%" PRIu64"]: <%zd/%" PRIu64"> <%" PRIu64"/%" PRIu64">\n",
         id, stream.my_offset, stream.his_max_data, my_sent_data, his_max_data);
    if(idle(id)){
        cleanStream(id);
    }
}

void QuicBase::close(uint64_t error) {
    walkHandler = [this](const quic_pkt_header* header, std::vector<const quic_frame*>& frames) -> int{
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
        close_timer = UpdateJob(std::move(close_timer),
                                [this]{onError(PROTOCOL_ERR, QUIC_CONNECTION_CLOSED);},
                                3 * qos.rtt.rttvar);
        return 0;
    };
    // RWER_CLOSING in quic means we have sent or recv CLOSE_CONNECTION_APP frame,
    // so we will not send CLOSE_CONNECTION_APP frame again
    if(isClosing){
        return;
    }
    isClosing = true;
    if(sslStats == SslStats::Established) {
        //we only send CLOSE_CONNECTION_APP frame after handshake now
        //TODO: but it should also be send before handshake
        close_timer = UpdateJob(std::move(close_timer),
                                [this]{onError(PROTOCOL_ERR, QUIC_CONNECTION_CLOSED);},
                                max_idle_timeout);

        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_CONNECTION_CLOSE_APP;
        frame->close.error = error;
        frame->close.frame_type = 0;
        frame->close.reason_len = 0;
        frame->close.reason = nullptr;
        qos.PushFrame(ssl_encryption_application, frame);
    }else{
        close_timer = UpdateJob(std::move(close_timer),
                                [this]{onError(PROTOCOL_ERR, QUIC_CONNECTION_CLOSED);}, 0);
    }
}

void QuicBase::getAlpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int QuicBase::setAlpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

bool QuicBase::checkStatelessReset(const void *may_be_token) {
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

void QuicBase::walkPacket(const void* buff, size_t length) {
    my_received_data_total += length;

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
            LOGE("QUIC meta unpack failed, disacrd it, body_len: %d, length: %d\n", body_len, (int)length);
            return;
        }
        if(ctx == nullptr && header.type == QUIC_PACKET_INITIAL && originDcid.empty()){
            //Init something for server
            originDcid = header.dcid;
            quic_generate_initial_key(0, header.dcid.data(), header.dcid.length(), &contexts[0].write_secret);
            quic_generate_initial_key(1, header.dcid.data(), header.dcid.length(), &contexts[0].read_secret);
            qos.KeyGot(ssl_encryption_initial);
            contexts[0].hasKey = true;
            onCidChange(originDcid, false);

            char quic_params[QUIC_INITIAL_LIMIT];
            SSL_set_quic_transport_params(ssl, (const uint8_t*)quic_params, generateParams(quic_params));
        }
        if (header.dcid != myids[myid_idx] && header.dcid != originDcid) {
            if(checkStatelessReset((char*)buff + body_len - QUIC_TOKEN_LEN)){
                LOGE("QUIC stateless reset with unkwnon dcid: %s\n",
                     dumpHex(header.dcid.data(), header.dcid.length()).c_str());
                onError(PROTOCOL_ERR, QUIC_CONNECTION_REFUSED);
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
                LOGD(DQUIC, "QUIC packet unpack failed, check stateless reset: %s\n",
                     dumpHex(header.dcid.data(), header.dcid.length()).c_str());
                if(checkStatelessReset((char*)buff + body_len - QUIC_TOKEN_LEN)){
                    LOGE("QUIC stateless reset\n");
                    onError(PROTOCOL_ERR, QUIC_CONNECTION_REFUSED);
                    return;
                }
                LOGE("QUIC packet unpack failed, discard it, type: 0x%02x, flag: %d, version: %u\n",
                     header.type, header.flags, header.version);
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

void QuicBase::reorderData(){
    for(auto& context : contexts) {
        if(!context.hasKey){
            continue;
        }
retry:
        bool skip_all = true;
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
                skip_all = false;
                continue;
            case FrameResult::skip:
                i++;
                continue;
            case FrameResult::error:
                return;
            }
        }
        if(!skip_all) {
            goto retry;
        }
    }
}

void QuicBase::walkPackets(const iovec *iov, int iovcnt) {
    for(int i = 0; i < iovcnt; i++){
        walkPacket(iov[i].iov_base, iov[i].iov_len);
    }
    if(!isClosing) {
        reorderData();
        sinkData(0);
    }
}

void QuicBase::reset(uint64_t id, uint32_t code) {
    if(streammap.count(id) == 0){
        return;
    }
    auto& stream = streammap[id];
    if((stream.flags & STREAM_FLAG_FIN_SENT) == 0){
        stream.flags |= STREAM_FLAG_FIN_SENT;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_RESET_STREAM;
        frame->reset.id = id;
        frame->reset.error = code;
        frame->reset.fsize = stream.my_offset;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    if((stream.flags & STREAM_FLAG_STOP_SENT) ==0){
        stream.flags |= STREAM_FLAG_STOP_SENT;
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_STOP_SENDING;
        frame->stop.id = id;
        frame->stop.error = code;
        qos.PushFrame(ssl_encryption_application, frame);
    }
}

void QuicBase::setResetHandler(std::function<void(uint64_t, uint32_t)> func) {
    resetHandler = std::move(func);
}

ssize_t QuicBase::window(uint64_t id) {
    if(streammap.count(id) == 0){
        return 0;
    }
    const auto& stream = streammap[id];
    if(stream.flags & STREAM_FLAG_FIN_SENT) {
        return 0;
    }
    assert(my_sent_data <= his_max_data);
    int streamcap = (int)stream.his_max_data - (int)stream.my_offset;
    int globalcap = (int)his_max_data - (int)my_sent_data;
    int window = std::max((int)qos.windowLeft(), BUF_LEN);
    return std::min({streamcap, globalcap, window});
}

size_t QuicBase::rlength(uint64_t id) {
    if(id == 0) {
        return rblen;
    }
    if(streammap.count(id) == 0){
        return 0;
    }
    return streammap[id].rb.length();
}

bool QuicBase::idle(uint64_t id){
    if(streammap.count(id) == 0){
        return true;
    }
    //这里收到reset也不认为是idle，因为即使收到reset，也不代表本端不会继续发送数据
    const auto& stream = streammap[id];
    bool send_closed = false;
    bool recv_closed = false;
    if(stream.flags & STREAM_FLAG_FIN_SENT){
        send_closed = true;
    }
    if(stream.flags & (STREAM_FLAG_FIN_DELIVED | STREAM_FLAG_RESET_DELIVED)){
        assert(stream.rb.length() == 0);
        recv_closed = true;
    }
    if((stream.flags & STREAM_FLAG_STOP_SENT) && (stream.flags & STREAM_FLAG_FIN_RECVD)){
        //这种情况下，stop sending已经发送了，但是因为对方已经发送了fin标记
        //因此不会回复reset包了，而应用层因为已经调用了reset，后续也不会接受fin标记
        //我们就视为fin标记已经被消费了
        recv_closed = true;
    }

    if(isBidirect(id)){
        return send_closed && recv_closed;
    }
    if(isLocal(id)){
        return send_closed;
    }
    return recv_closed;
}

bool QuicBase::canSend(uint64_t id) {
    if(streammap.count(id) == 0){
        return true;
    }
    const auto& stream = streammap[id];
    if(stream.flags & STREAM_FLAG_FIN_SENT){
        return false;
    }
    if(isBidirect(id)) {
        return true;
    }
    return isLocal(id);
}

void QuicBase::sinkData(uint64_t id, QuicStreamStatus &status) {
    if(status.flags & (STREAM_FLAG_FIN_DELIVED | STREAM_FLAG_RESET_RECVD)){
        return;
    }
    auto& rb = status.rb;
    assert(rblen >= rb.length());
    if(rb.length() > 0){
        Buffer bb = rb.get();
        bb.id = id;
        size_t eaten = onRead(std::move(bb));
        LOGD(DQUIC, "consume data [%" PRIu64"]: %" PRIu64" - %" PRIu64", left: %zd\n",
             id, rb.Offset(), rb.Offset() + eaten, rb.length() - eaten);
        rb.consume(eaten);
        rblen -= eaten;
    }

    if((status.flags & STREAM_FLAG_FIN_RECVD) &&
       (rb.Offset() == status.finSize || status.flags & STREAM_FLAG_RESET_RECVD))
    {
        assert((status.flags & STREAM_FLAG_FIN_DELIVED) == 0);
        //在QuicRWer中，我们不用 ReadEOF状态，因为它是对整个连接的，而不是对某个stream的
        onRead({nullptr, id});
        LOGD(DQUIC, "consume EOF [%" PRIu64"]: %" PRIu64"\n", id, rb.Offset());
        status.flags |= STREAM_FLAG_FIN_DELIVED;
    }

    if(!isBidirect(id) && isLocal(id)) {
        return;
    }
    auto shouldSendMaxStreamData = [](QuicStreamStatus& status) -> bool {
        if((status.flags & STREAM_FLAG_FIN_RECVD) && status.my_max_data >= status.finSize){
            return false;
        }
        uint64_t rcap = status.rb.Offset() + status.rb.length() + status.rb.cap();
        if(status.my_max_data - status.his_offset < BUF_LEN/2 && rcap > status.my_max_data){
            return true;
        }
        if(rcap - status.my_max_data < BUF_LEN){
            return false;
        }
        return true;
    };
    if(shouldSendMaxStreamData(status)){
        status.my_max_data =  rb.Offset() + rb.length() + rb.cap();
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_MAX_STREAM_DATA;
        frame->max_stream_data.id = id;
        frame->max_stream_data.max = status.my_max_data;
        qos.PushFrame(ssl_encryption_application, frame);
    }
}

void QuicBase::sinkData(uint64_t id) {
    std::list<uint64_t> to_clean;
    if(id == 0) {
        for (auto& [id, stream]: streammap) {
            sinkData(id, stream);
            if (idle(id)) {
                to_clean.push_back(id);
            }
        }
    } else if(streammap.count(id)){
        sinkData(id, streammap[id]);
        if (idle(id)) {
            to_clean.push_back(id);
        }
    }
    if (my_max_data - my_received_data <= 50 * 1024 * 1024) {
        my_max_data += 50 * 1024 * 1024;
        quic_frame *frame = new quic_frame;
        frame->type = QUIC_FRAME_MAX_DATA;
        frame->extra = my_max_data;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    if (my_max_streams_bidi - my_received_max_bidistream_id / 4 <= 100) {
        my_max_streams_bidi += 100;
        quic_frame *frame = new quic_frame;
        frame->type = QUIC_FRAME_MAX_STREAMS_BI;
        frame->extra = my_max_streams_bidi;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    if (my_max_streams_uni - my_received_max_unistream_id / 4 <= 100) {
        my_max_streams_uni += 100;
        quic_frame *frame = new quic_frame;
        frame->type = QUIC_FRAME_MAX_STREAMS_UBI;
        frame->extra = my_max_streams_uni;
        qos.PushFrame(ssl_encryption_application, frame);
    }
    for(auto& i: to_clean){
        cleanStream(i);
    }
}

uint64_t QuicBase::createBiStream() {
    uint64_t id = nextLocalBiId;
    nextLocalBiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = my_max_stream_data_bidi_local;
    stat.his_max_data = his_max_stream_data_bidi_remote;
    streammap.emplace(id, std::move(stat));
    return id;
}

uint64_t QuicBase::createUbiStream() {
    uint64_t id = nextLocalUbiId;
    nextLocalUbiId += 4;
    QuicStreamStatus stat{};
    stat.my_max_data = 0;
    stat.his_max_data = his_max_stream_data_uni;
    streammap.emplace(id, std::move(stat));
    return id;
}

void QuicBase::disconnect_action() {
    if(isClosing){
        return;
    }
    onError(PROTOCOL_ERR, QUIC_NO_ERROR);
}

void QuicBase::keepAlive_action() {
    assert(contexts[ssl_encryption_application].hasKey);
    if(isClosing){
        return;
    }
    qos.PushFrame(ssl_encryption_application, new quic_frame{QUIC_FRAME_PING, {}});
}

void QuicBase::dump(Dumper dp, void* param) {
    dp(param, "%s -> %s, max_payload: %zd, max_bistream: %zd/%zd, max_unistream: %zd/%zd\n"
              "read: %zd/%zd, write: %zd/%zd, my_window: %zd, his_window: %zd, "
              "rlen: %zd, fullq: %zd, wlen: %zd, congestion_window: %d\n",
       dumpHex(myids[myid_idx].c_str(), myids[myid_idx].length()).c_str(),
       dumpHex(hisids[hisid_idx].c_str(), hisids[hisid_idx].length()).c_str(),
       his_max_payload_size,
       my_received_max_bidistream_id, my_max_streams_bidi,
       my_received_max_unistream_id, my_max_streams_uni,
       my_received_data, my_received_data_total,
       my_sent_data, my_sent_data_total,
       my_max_data - my_received_data,
       his_max_data - my_sent_data,
       rblen, fullq.size(),
       qos.PendingSize(ssl_encryption_application), (int)qos.windowLeft());
    for(const auto& [id, stream]: streammap){
        dp(param, "  0x%lx: rlen: %zd-%zd, rcap: %zd, my_window: %zd, his_window: %zd, flags: 0x%08x\n",
           id, stream.rb.Offset(), stream.rb.Offset() + stream.rb.length(),
           stream.rb.cap() + stream.rb.length() + stream.rb.Offset() - stream.my_max_data,
           stream.my_max_data - stream.his_offset, stream.his_max_data - stream.my_offset, stream.flags);
    }
}

size_t QuicBase::mem_usage() {
    size_t usage = sizeof(*this) + qos.mem_usage();
    for(const auto& context : contexts){
        for(const auto& frame : context.recvq.data){
            usage += frame_size(frame);
        }
    }
    usage += myids.size() * sizeof(std::string);
    for(const auto& id: myids) {
        usage += id.capacity();
    }
    usage += hisids.size() * sizeof(std::string);
    for(const auto& id: hisids) {
        usage += id.capacity();
    }
    usage += histoken.size() * sizeof(std::string);
    for(const auto& token: histoken) {
        usage += token.capacity();
    }
    usage += initToken.length() + originDcid.length();
    for(const auto& [id, stream] : streammap) {
        usage += sizeof(id) + sizeof(stream);
        usage += stream.rb.cap() + stream.rb.length();
    }
    usage += fullq.size() * sizeof(quic_frame*);
    for(const auto& frame: fullq) {
        usage += frame_size(frame);
    }
    return usage;
}


QuicRWer::QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                   std::shared_ptr<IRWerCallback> cb):
        QuicBase(hostname), SocketRWer(hostname, port, protocol, std::move(cb))
{
    assert(protocol == Protocol::QUIC);
    con_failed_job = UpdateJob(std::move(con_failed_job),
                               [this]{connectFailed(ETIMEDOUT);}, 2000);
}

QuicRWer::QuicRWer(int fd, const sockaddr_storage *peer, SSL_CTX *ctx, Quic_server* server):
        QuicBase(ctx), 
        SocketRWer(fd, peer, ISocketCallback::create()->onError([](int, int){})),
        server(server)
{
    server->rwers.emplace(myids[0], this);
}

size_t QuicRWer::getWritableSize() {
    if(sndbuf == 0) {
        sndbuf = GetCapSize(getFd());
    }
    return (sndbuf - GetBuffSize(getFd()))/2;
}

ssize_t QuicRWer::writem(const struct iovec *iov, int iovcnt) {
    if(iovcnt == 1) {
        return write(getFd(), iov[0].iov_base, iov[0].iov_len) == (int)iov[0].iov_len ? 1 : -1;
    }
    return ::writem(getFd(), iov, iovcnt);
}

void QuicRWer::onConnected() {
    connected(addrs.front());
}

size_t QuicRWer::onRead(Buffer&& bb) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    if(auto cb = callback.lock(); cb) {
        return cb->readCB(std::move(bb));
    }
    return 0;
}

void QuicRWer::onWrite(uint64_t id) {
    if(auto cb = callback.lock(); cb) {
        cb->writeCB(id);
    }
}


void QuicRWer::onCidChange(const std::string &cid, bool retired) {
    if (retired) {
        server->rwers.erase(cid);
    } else {
        server->rwers.emplace(cid, this);
    }
}

int QuicRWer::handleRetryPacket(const quic_pkt_header *header) {
    if(initToken.empty()) {
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   [this]{connect();}, 20000);
    }
    return QuicBase::handleRetryPacket(header);
}

void QuicRWer::onError(int type, int code) {
    if (type == PROTOCOL_ERR && code == QUIC_CONNECTION_CLOSED) {
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    } else {
        stats = RWerStats::Error;
        if (auto cb = callback.lock(); cb) {
            cb->errorCB(type, code);
        }
    }
}

bool QuicRWer::IsConnected() {
    return sslStats == SslStats::Established;
}

void QuicRWer::ReadData() {
    Block blk(IOV_MAX*max_datagram_size);
    std::vector<iovec> iov;
    iov.resize(IOV_MAX);
    for(size_t i = 0; i < iov.size(); i++) {
        iov[i].iov_base = (char*)blk.data() + i * max_datagram_size;
        iov[i].iov_len = max_datagram_size;
    }
    ssize_t ret = readm(getFd(), iov.data(), iov.size());
    LOGD(DQUIC, "readm from %d, size: %zd ret:%d\n", getFd(), iov.size(), (int)ret);
    if (ret < 0 && errno == EAGAIN) {
        return;
    }
    if (ret < 0) {
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    walkPackets(iov.data(), ret);
}

void QuicRWer::Send(Buffer&& bb) {
    if(stats == RWerStats::Error){
        return;
    }
    sendData(std::move(bb));
}

void QuicRWer::ConsumeRData(uint64_t id) {
    if (stats == RWerStats::Error) {
        return;
    }
    sinkData(id);
}


size_t QuicRWer::rlength(uint64_t id) {
    return QuicBase::rlength(id);
}

void QuicRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        int error  = checkSocket(__PRETTY_FUNCTION__);
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   ([this, error]{connectFailed(error);}), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        assert(!addrs.empty());
        if (doSslConnect(hostname)) {
            return;
        }
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&QuicRWer::defaultHE;
        con_failed_job = UpdateJob(std::move(con_failed_job),
                                   [this]{connectFailed(ETIMEDOUT);}, 2000);
    }
}

void QuicRWer::Close() {
    if (flags & RWER_CLOSING) {
        return;
    }
    flags |= RWER_CLOSING;
    if(stats == RWerStats::Error) {
        setEvents(RW_EVENT::NONE);
        if(auto cb = callback.lock(); cb) {
            close_timer = UpdateJob(std::move(close_timer), [cb]{cb->closeCB();}, 0);
        }
    }else if(getFd() >= 0) {
        handleEvent = (void (Ep::*)(RW_EVENT))&QuicRWer::closeHE;
        setEvents(RW_EVENT::READ);
        close(QUIC_APPLICATION_ERROR);
    } else {
        return onError(PROTOCOL_ERR, QUIC_NO_ERROR);
    }
}

void QuicRWer::closeHE(RW_EVENT events) {
    if(!(events & RW_EVENT::READ)) {
        return;
    }
    char buff[max_datagram_size];
    while(true) {
        ssize_t ret = read(getFd(), buff, sizeof(buff));
        LOGD(DQUIC, "read from %d when closing, size: %zd ret:%d\n", getFd(), sizeof(buff), (int)ret);
        if (ret < 0 && errno == EAGAIN) {
            return;
        }
        if (ret < 0) {
            LOGE("read error when closing %d: %s\n", getFd(), strerror(errno));
            return onError(PROTOCOL_ERR, QUIC_NO_ERROR);
        }
        walkPacket(buff, ret);
    }
}

void QuicRWer::ErrorHE(int type, int code) {
    if(type == SOCKET_ERR && code == EMSGSIZE) {
#if defined(IP_MTU) && defined(IPV6_MTU)
        int mtu;
        socklen_t mtulen = sizeof(mtu);
        bool isIpv6 = addrs.front().ss_family == AF_INET6;
        if(isIpv6) {
            if(getsockopt(getFd(), IPPROTO_IPV6, IPV6_MTU, &mtu, &mtulen) == 0) {
                mtu -= 40 + 8; //ipv6 header + udp header
                goto success;
            }
        } else {
            if(getsockopt(getFd(), IPPROTO_IP, IP_MTU, &mtu, &mtulen) == 0) {
                mtu -= 20 + 8; //ipv4 header + udp header
                goto success;
            }
        }
        LOGE("faile to get ip_mtu: %s\n", strerror(errno));
        return RWer::ErrorHE(type, code);
success:
        if(mtu < (int)his_max_payload_size) {
            LOG("quic max payload size reduce to %d due to pmtu\n", mtu);
            his_max_payload_size = mtu;
        }
#else
        his_max_payload_size =  1200;
#endif
    } else if(type == SOCKET_ERR && code == 0) {
        //recreate socket
        sockaddr_storage myaddr, hisaddr;
        socklen_t mylen = sizeof(myaddr);
        socklen_t hislen = sizeof(hisaddr);
        if(getpeername(getFd(), (sockaddr*)&hisaddr, &hislen)) {
            LOGE("getpeername failed: %s\n", strerror(errno));
            return RWer::ErrorHE(type, code);
        }
        if(getsockname(getFd(), (sockaddr*)&myaddr, &mylen)) {
            LOGE("getsockname failed: %s\n", strerror(errno));
            return RWer::ErrorHE(type, code);
        }
        int clsk = ListenUdp(&myaddr, nullptr);
        if (clsk < 0) {
            LOGE("ListenNet %s, failed: %s\n", storage_ntoa(&myaddr), strerror(errno));
            return RWer::ErrorHE(type, code);
        }
        if (::connect(clsk, (sockaddr *)&hisaddr, hislen) < 0) {
            LOGE("connect %s failed: %s\n", storage_ntoa(&hisaddr), strerror(errno));
            return RWer::ErrorHE(type, code);
        }
        LOGD(DQUIC, "reconnect udp %d to %s\n", clsk, storage_ntoa(&hisaddr));
        SetUdpOptions(clsk, &hisaddr);
        setFd(clsk);
    } else {
        RWer::ErrorHE(type, code);
    }
}


QuicRWer::~QuicRWer() {
    if(server == nullptr){
        return;
    }
    for(const auto& id: myids){
        server->rwers.erase(id);
    }
    server->rwers.erase(originDcid);
}

void QuicRWer::dump_status(Dumper dp, void *param) {
    if(hostname[0]) {
        dp(param, "Quic <%d> (%s  %s), stats: %d, events: %s\n",
                getFd(), hostname, dumpDest(getDst()).c_str(),
                (int)getStats(), events_string[(int)getEvents()]);
    }else {
        dp(param, "Quic <%d> (%s - %s), stats: %d, events: %s\n",
                getFd(), dumpDest(getSrc()).c_str(), dumpDest(getDst()).c_str(),
                (int)getStats(), events_string[(int)getEvents()]);
    }
    return dump(dp, param);
}

size_t QuicRWer::mem_usage() {
    return QuicBase::mem_usage() + sizeof(*this);
}

QuicMer::QuicMer(SSL_CTX *ctx, const Destination& src,
                 std::shared_ptr<IMemRWerCallback> _cb):
        QuicBase(ctx), MemRWer(src, std::move(_cb))
{
}

size_t QuicMer::getWritableSize() {
    if(auto cb = _callback.lock(); cb) {
        return cb->cap_cb();
    }
    return 0;
}

ssize_t QuicMer::writem(const struct iovec *iov, int iovcnt) {
    if(_callback.expired()) {
        LOGE("callback expired, cannot write data\n");
        return -1;
    }
    auto write_cb = _callback.lock()->write_cb;
    for (int i = 0; i < iovcnt; i++) {
        if(write_cb(Buffer{iov[i].iov_base, (size_t)iov[i].iov_len}) < 0){
            return i;
        }
    }
    return iovcnt;
}

void QuicMer::onConnected() {
    connected({});
}

void QuicMer::onError(int type, int code) {
    if (type == PROTOCOL_ERR && code == QUIC_CONNECTION_CLOSED) {
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    } else {
        stats = RWerStats::Error;
        if(auto cb = callback.lock(); cb) {
            cb->errorCB(type, code);
        }
    }
}

size_t QuicMer::onRead(Buffer&& bb) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    if(auto cb = callback.lock(); cb) {
        return cb->readCB(std::move(bb));
    }
    return 0;
}

void QuicMer::onWrite(uint64_t id) {
    if(auto cb = callback.lock(); cb) {
        cb->writeCB(id);
    }
}

void QuicMer::defaultHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        ErrorHE(SOCKET_ERR, checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    setEvents(RW_EVENT::NONE);
}

void QuicMer::push_data(Buffer&& bb) {
    if(flags & RWER_CLOSING){
        return;
    }
    walkPacket(bb.data(), bb.len);
    if(!isClosing) {
        reorderData();
        sinkData(0);
    }
}

void QuicMer::Send(Buffer&& bb) {
    if(stats == RWerStats::Error){
        return;
    }
    sendData(std::move(bb));
}

bool QuicMer::IsConnected() {
    return sslStats == SslStats::Established;
}

void QuicMer::ConsumeRData(uint64_t id) {
    if (stats == RWerStats::Error) {
        return;
    }
    sinkData(id);
}

void QuicMer::Close() {
    if (flags & RWER_CLOSING) {
        return;
    }
    flags |= RWER_CLOSING;
    if(getFd() >= 0) {
        handleEvent = (void (Ep::*)(RW_EVENT)) &QuicMer::closeHE;
        setEvents(RW_EVENT::READ);
        close(QUIC_APPLICATION_ERROR);
    } else {
        //只有一种情况会走到这里，就是对端发送了ABORT信号断开了连接
        if(auto cb = callback.lock(); cb) {
            cb->closeCB();
        }
    }
}

void QuicMer::dump_status(Dumper dp, void *param) {
    dp(param, "Quic <%d> (%s), stats: %d, flags: 0x%04x,  event: %s\n",
        getFd(), dumpDest(getSrc()).c_str(), (int)getStats(), flags, events_string[(int)getEvents()]);
    return dump(dp, param);
}

size_t QuicMer::mem_usage() {
    return QuicBase::mem_usage() + sizeof(*this);
}
