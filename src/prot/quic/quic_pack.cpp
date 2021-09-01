#include "quic_pack.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <openssl/kdf.h>
#include <openssl/tls1.h>


/* 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
static const char* initial_salt = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
static const int initial_saltlen = 20;

static void dumphex(const void* s_, size_t len){
    const unsigned  char* s = (const unsigned  char*)s_;
    for(size_t i = 0; i < len; i++){
        printf("%02x", (unsigned char)(s[i]));
        if(i%32==31){
            printf("\n");
        }else if(i%16 == 15){
            printf(" ");
        }
    }
    printf("\n");
}

size_t variable_encode_len(uint64_t value){
    if(value <= 63){
        return 1;
    }
    if(value <= 16383){
        return 2;
    }
    if(value <= 1073741823){
        return 4;
    }
    if(value <= 4611686018427387903) {
        return 8;
    }
    return 0;
}

size_t variable_encode(void* data_, uint64_t value){
    unsigned char* data = (unsigned  char*)data_;
    if(value <= 63){
        data[0] = (unsigned char)value;
        return 1;
    }
    if(value <= 16383){
        set16(data, value);
        data[0] |= 0x40;
        return 2;
    }
    if(value <= 1073741823){
        set32(data, value);
        data[0] |= 0x80;
        return 4;
    }
    if(value <= 4611686018427387903) {
        set64(data, value);
        data[0] |= 0xc0;
        return 8;
    }
    abort();
}

size_t variable_decode(const void* data_, uint64_t* value){
    const unsigned char* data = (const unsigned  char*)data_;
    size_t size = 1 << (data[0] >> 6);
    *value = data[0] & 0x3f;
    for(size_t i = 1; i < size; i ++){
        *value <<= 8;
        *value += data[i];
    }
    return size;
}

size_t variable_decode_len(const void* data_){
    const unsigned char* data = (const unsigned  char*)data_;
    return 1 << (data[0] >> 6);
}

//only used for initial key, so just use EVP_sha256
static int HKDF_Extract(const char* cid, size_t clen, char* prk){
    size_t hashlen = EVP_MD_size(EVP_sha256());
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, initial_salt, initial_saltlen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, cid, clen) <= 0)
        goto err;
    if(EVP_PKEY_derive(pctx, (unsigned char*)prk, &hashlen) <=0 )
        goto err;
    EVP_PKEY_CTX_free(pctx);
    return 1;
err:
    EVP_PKEY_CTX_free(pctx);
    return -1;
}

typedef struct HkdfLabel{
    uint16_t length;
    uint8_t  infoLen;
    char content[0];
} __attribute__((packed)) HkdfLabel;

static int HKDF_Expand_Label(const EVP_MD* md, const char* prk, const char* info, const char *msg, char* okm, size_t len){
    size_t infoLen = strlen(info);
    size_t msgLen = strlen(msg);
    size_t labelLen = sizeof(struct HkdfLabel) + 6 + infoLen + 1 + msgLen;
    if(labelLen > 255){
        return -1;
    }
    struct HkdfLabel *label = (HkdfLabel*)malloc(255);
    label->length = htons(len);
    label->infoLen = infoLen + 6;
    int pos = 0;
    memcpy(label->content, "tls13 ", 6);
    pos += 6;
    memcpy(label->content + pos, info, infoLen);
    pos += infoLen;
    label->content[pos++] = msgLen;
    memcpy(label->content + pos, msg, msgLen);
    size_t hashlen = EVP_MD_size(md);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, hashlen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, labelLen) <= 0)
        goto err;
    if(EVP_PKEY_derive(pctx, (unsigned char*)okm, &len) <=0 )
        goto err;
    free(label);
    EVP_PKEY_CTX_free(pctx);
    return 1;
err:
    free(label);
    EVP_PKEY_CTX_free(pctx);
    return -1;
}

static int aead_encrypt(const EVP_CIPHER* cipher,
                       const unsigned char *plaintext, int plaintext_len,
                       const unsigned char *aad, int aad_len,
                       const unsigned char *key,
                       const unsigned char *iv,
                       unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    /* Create and initialise the context */
    if(ctx == NULL)
        return -1;
    /* Initialise the encryption operation. */
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1)
        goto err;

    /* Initialise key and IV */
    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto err;
    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
        goto err;
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto err;
    ciphertext_len = len;
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len) != 1)
        goto err;
    ciphertext_len += len;

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext + ciphertext_len) != 1)
        goto err;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + 16;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


static int aead_decrypt(const EVP_CIPHER* cipher,
                       unsigned char *ciphertext, int ciphertext_len,
                       unsigned char *aad, int aad_len,
                       unsigned char *key,
                       unsigned char *iv,
                       unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    /* Create and initialise the context */
    if(ctx == NULL)
        return -1;

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        goto err;

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        goto err;

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        goto err;

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len - 16))
        goto err;

    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ciphertext + ciphertext_len - 16))
        goto err;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0)
        goto err;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    plaintext_len += len;
    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int hp_encode(const EVP_CIPHER* cipher,
                      const unsigned char* key,
                      const unsigned char* data, int data_len,
                      unsigned char* out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, outlen;
    if(ctx == NULL)
        return -1;
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) != 1)
        goto err;

    if(EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
        goto err;

    if(EVP_EncryptUpdate(ctx, out, &len, data, data_len) != 1)
        goto err;
    outlen = len;

    if(EVP_EncryptFinal_ex(ctx, out+len, &len) != 1)
        goto err;

    outlen += len;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


int quic_generate_initial_key(int client, const char* id, uint8_t id_len, struct quic_secret* secret){
    char prk[32];
    if(HKDF_Extract(id, id_len, prk) < 0){
        LOGE("initial_secret failed\n");
        return -1;
    }
    secret->cipher = EVP_aes_128_gcm();
    secret->md = EVP_sha256();
    secret->hcipher = EVP_aes_128_ecb();
    char initial_secret[32];
    if(client) {
        if (HKDF_Expand_Label(secret->md, prk, "client in", "", initial_secret, 32) < 0) {
            LOGE("client_initial_secret failed\n");
            return -1;
        }
    }else{
        if (HKDF_Expand_Label(secret->md, prk, "server in", "", initial_secret, 32) < 0) {
            LOGE("client_initial_secret failed\n");
            return -1;
        }
    }

    if(HKDF_Expand_Label(secret->md, initial_secret, "quic key", "", secret->key, 16) < 0){
        LOGE("quic key failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, initial_secret, "quic iv", "", secret->iv, 12) < 0){
        LOGE("quic iv failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, initial_secret, "quic hp", "", secret->hp, 16) < 0){
        LOGE("quic hp failed\n");
        return -1;
    }
    return 0;
}

int quic_secret_set_key(struct quic_secret* secret, const char* key, uint32_t cipher){
    size_t hp_len = 0;
    size_t key_len = 0;
    switch (cipher) {
    case TLS1_3_CK_AES_128_GCM_SHA256:
        secret->hcipher = EVP_aes_128_ecb();
        secret->cipher = EVP_aes_128_gcm();
        secret->md = EVP_sha256();
        key_len = 16;
        hp_len = 16;
        break;
    case TLS1_3_CK_AES_256_GCM_SHA384:
        secret->hcipher = EVP_aes_256_ecb();
        secret->cipher = EVP_aes_256_gcm();
        secret->md = EVP_sha384();
        key_len = 32;
        hp_len = 16;
        break;
    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
        secret->hcipher = EVP_chacha20();
        secret->cipher = EVP_chacha20_poly1305();
        secret->md = EVP_sha256();
        key_len = 32;
        hp_len = 32;
        break;
    case TLS1_3_CK_AES_128_CCM_SHA256:
        secret->hcipher = EVP_aes_128_ecb();
        secret->cipher = EVP_aes_128_ccm();
        secret->md = EVP_sha256();
        key_len = 16;
        hp_len = 16;
        break;
    default:
        LOGE("unknow cipher: %d\n", cipher);
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, key, "quic key", "", secret->key, key_len) < 0){
        LOGE("quic key failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, key, "quic iv", "", secret->iv, 12) < 0){
        LOGE("quic iv failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, key, "quic hp", "", secret->hp, hp_len) < 0){
        LOGE("quic hp failed\n");
        return -1;
    }
    return 0;
}

static int pack_header(const struct quic_pkt_header* header, char* data, uint16_t data_len){
    uint8_t pn_len = header->pn_length;
    assert(pn_len <= 4 && pn_len >=1);
    size_t p = 0;
    if(header->meta.type == QUIC_PACKET_1RTT){
        data[0] = 0x40 | header->meta.flags | (pn_len - 1);
        memcpy(data + 1, header->meta.dcid.data(), header->meta.dcid.length());
        p = 1 + header->meta.dcid.length();
    }else{
        data[0] = 0xc0 | header->meta.type | (pn_len - 1);
        if(header->meta.version){
            set32(data+1, header->meta.version);
        }else{
            set32(data+1, QUIC_VERSION_1);
        }
        p = 5;
        p += variable_encode(data + p, header->meta.dcid.length());
        memcpy(data + p, header->meta.dcid.data(), header->meta.dcid.length());
        p += header->meta.dcid.length();
        p += variable_encode(data + p, header->meta.scid.length());
        memcpy(data + p, header->meta.scid.data(), header->meta.scid.length());
        p += header->meta.scid.length();
        if(header->meta.type == QUIC_PACKET_INITIAL) {
            p += variable_encode(data + p, header->meta.token.length());
            if (!header->meta.token.empty()) {
                memcpy(data + p, header->meta.token.data(), header->meta.token.length());
                p += header->meta.token.length();
            }
        }
        p += variable_encode(data + p, data_len + pn_len);
    }
    switch(pn_len) {
    case 1:
        data[p] = header->pn & 0xff;
        break;
    case 2:
        set16(data +p , header->pn & 0xffff)
        break;
    case 3:
        set24(data + p, header->pn & 0xffffff)
        break;
    case 4:
        set32(data + p, header->pn & 0xffffffff);
        break;
    default:
        abort();
    }
    return  (int)p + pn_len;
}


char* encode_packet(const void* data_, size_t len,
                  const quic_pkt_header* header, const quic_secret* secret,
                  char* body){

    size_t header_len = pack_header(header, body, len + 16);
    char iv[12];
    memcpy(iv, secret->iv, 12);
    for(int i = 0; i < 8; i++){
        iv[11-i] ^= (header->pn>>(i*8))&0xff;
    }
    size_t pn_length = (body[0] & 0x03) + 1;
    assert(pn_length == header->pn_length);

    int ciphertext_len = aead_encrypt(
            secret->cipher,
            (const unsigned char*)data_,
            len,
            (const unsigned char*)body,
            header_len,
            (const unsigned char*)secret->key,
            (const unsigned char*)iv,
            (unsigned char*)body + header_len);
    if(ciphertext_len < 0){
        LOGE("gcm_encrypt error\n");
        return nullptr;
    }

    unsigned char mask[128];
    memset(mask, 0, 128);
    char* pos = body;
    if((body[0] & 0x80) == 0x80){ // long header
        pos += 7 + header->meta.dcid.length() + header->meta.scid.length();
        if(header->meta.type == QUIC_PACKET_INITIAL) {
            uint64_t token_len;
            pos += variable_decode(pos, &token_len);
            assert(token_len == header->meta.token.length());
            pos += header->meta.token.length();
        }

        uint64_t payload_len;
        pos += variable_decode(pos, &payload_len);
        assert(payload_len == len + pn_length + 16);

        int mask_len = hp_encode(secret->hcipher, (unsigned char*)secret->hp, (unsigned char*)pos + 4, 16, mask);
        if(mask_len < 0){
            LOGE("aes_encode failed\n");
            return nullptr;
        }
        body[0] ^= mask[0] & 0x0f;
    }else{
        pos += 1 + header->meta.dcid.length();

        if(hp_encode(secret->hcipher, (unsigned char*)secret->hp, (unsigned char*)pos + 4, 16, mask) < 0){
            LOGE("aes_encode failed\n");
            return nullptr;
        }
        body[0] ^= mask[0] & 0x1f;
    }
    for(size_t i = 0; i < pn_length; i++){
        pos[i] ^= mask[i + 1];
    }
    return body + header_len + ciphertext_len;
}

static char* pack_crypto_frame(const struct quic_crypto* crypto, char* data){
    data += variable_encode(data, crypto->offset);
    data += variable_encode(data, crypto->length);
    memcpy(data, crypto->body, crypto->length);
    return data + crypto->length;
}

static const char* unpack_crypto_frame(const char* data, struct quic_crypto* crypto){
    data += variable_decode(data, &crypto->offset);
    data += variable_decode(data, &crypto->length);
    crypto->body = new char[crypto->length];
    memcpy(crypto->body, data, crypto->length);
    return data + crypto->length;
}

static char* pack_ack_frame(const struct quic_ack* ack, char* data){
    data += variable_encode(data, ack->acknowledged);
    data += variable_encode(data, ack->delay);
    data += variable_encode(data, ack->range_count);
    data += variable_encode(data, ack->first_range);
    for(size_t i = 0; i < ack->range_count; i++){
        data += variable_encode(data, ack->ranges[i].gap);
        data += variable_encode(data, ack->ranges[i].length);
    }
    return data;
}

static char* pack_ack_ecn_frame(const struct quic_ack* ack, char* data){
    data += variable_encode(data, ack->ecns.ect0);
    data += variable_encode(data, ack->ecns.ect1);
    data += variable_encode(data, ack->ecns.ecn_ce);
    return data;
}

static const char* unpack_ack_frame(uint64_t type, const char* data, struct quic_ack* ack){
    assert(type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN);
    data += variable_decode(data, &ack->acknowledged);
    data += variable_decode(data, &ack->delay);
    data += variable_decode(data, &ack->range_count);
    data += variable_decode(data, &ack->first_range);
    if(ack->range_count){
        ack->ranges = new quic_ack_range[ack->range_count];
        for(size_t i = 0 ; i < ack->range_count; i++){
            data += variable_decode(data, &ack->ranges[i].gap);
            data += variable_decode(data, &ack->ranges[i].length);
        }
    }else{
        ack->ranges = nullptr;
    }
    if(type == QUIC_FRAME_ACK_ECN){
        data += variable_decode(data, &ack->ecns.ect0);
        data += variable_decode(data, &ack->ecns.ect1);
        data += variable_decode(data, &ack->ecns.ecn_ce);
    }
    return data;
}

static char* pack_close_frame(uint64_t type, const struct quic_close* close_frame, char* data){
    assert(type == QUIC_FRAME_CONNECTION_CLOSE || type == QUIC_FRAME_CONNECTION_CLOSE_APP);
    data += variable_encode(data, close_frame->error);
    if(type == QUIC_FRAME_CONNECTION_CLOSE){
        data += variable_encode(data, close_frame->frame_type);
    }
    data += variable_encode(data, close_frame->reason_len);
    memcpy(data, close_frame->reason, close_frame->reason_len);
    return data + close_frame->reason_len;
}

static const char* unpack_close_frame(uint64_t type, const char* data, struct quic_close* close_frame){
    assert(type == QUIC_FRAME_CONNECTION_CLOSE || type == QUIC_FRAME_CONNECTION_CLOSE_APP);
    data += variable_decode(data, &close_frame->error);
    if(type == QUIC_FRAME_CONNECTION_CLOSE_APP){
        close_frame->frame_type = QUIC_FRAME_PADDING;
    }else{
        data += variable_decode(data, &close_frame->frame_type);
    }
    data += variable_decode(data, &close_frame->reason_len);
    close_frame->reason = new char[close_frame->reason_len];
    memcpy(close_frame->reason, data, close_frame->reason_len);
    return data + close_frame->reason_len;
}

static char* pack_new_id_frame(const struct quic_new_id* new_id, char* data){
    data += variable_encode(data, new_id->seq);
    data += variable_encode(data, new_id->retired);
    data[0] = (char)new_id->length;
    data ++;
    memcpy(data, new_id->id, new_id->length);
    data += new_id->length;
    memcpy(data, new_id->token, sizeof(new_id->token));
    return data + sizeof(new_id->token);
}

static const char* unpack_new_id_frame(const char* data, struct quic_new_id* new_id){
    data += variable_decode(data, &new_id->seq);
    data += variable_decode(data, &new_id->retired);
    new_id->length = data[0];
    data ++;
    new_id->id = new char[new_id->length];
    memcpy(new_id->id, data, new_id->length);
    data += new_id->length;
    memcpy(new_id->token, data, sizeof(new_id->token));
    return data + sizeof(new_id->token);
}

static char* pack_new_token_frame(const quic_new_token* new_token, char* data){
    data += variable_encode(data, new_token->length);
    memcpy(data, new_token->token, new_token->length);
    return data + new_token->length;
}

static const char* unpack_new_token_frame(const char* data, struct quic_new_token* new_token){
    data += variable_decode(data, &new_token->length);
    new_token->token = new char[new_token->length];
    memcpy(new_token->token, data, new_token->length);
    return data + new_token->length;
}

static char* pack_stream_frame(uint64_t type, const quic_stream* stream, char *data){
    assert((type >= QUIC_FRAME_STREAM_START_ID)
        && (type <= QUIC_FRAME_STREAM_END_ID));
    data += variable_encode(data, stream->id);
    if(type & QUIC_FRAME_STREAM_OFF_F){
        data += variable_encode(data, stream->offset);
    }
    if(type & QUIC_FRAME_STREAM_LEN_F){
        data += variable_encode(data, stream->length);
    }
    memcpy(data, stream->data, stream->length);
    return data + stream->length;
}

static const char* unpack_stream_frame(uint64_t type, const char* data, int len, quic_stream* stream) {
    data += variable_decode(data, &stream->id);
    if(type & QUIC_FRAME_STREAM_OFF_F){
        data += variable_decode(data, &stream->offset);
    }else{
        stream->offset = 0;
    }
    if(type & QUIC_FRAME_STREAM_LEN_F){
        data += variable_decode(data, &stream->length);
    }else{
        stream->length = len - (data - data);
    }
    stream->data = new char[stream->length];
    memcpy(stream->data, data, stream->length);
    return data + stream->length;
}

static char* pack_reset_frame(const quic_reset* reset, char* data){
    data += variable_encode(data, reset->id);
    data += variable_encode(data, reset->error);
    data += variable_encode(data, reset->fsize);
    return data;
}

static const char* unpack_reset_frame(const char* data, quic_reset* reset){
    data += variable_decode(data, &reset->id);
    data += variable_decode(data, &reset->error);
    data += variable_decode(data, &reset->fsize);
    return data;
}

static char* pack_stop_frame(const quic_stop* stop, char* data){
    data += variable_encode(data, stop->id);
    data += variable_encode(data, stop->error);
    return data;
}

static const char* unpack_stop_frame(const char* data, quic_stop* stop){
    data += variable_decode(data, &stop->id);
    data += variable_decode(data, &stop->error);
    return data;
}

static char* pack_max_stream_data(const quic_max_stream_data* stream_data, char* data){
    data += variable_encode(data, stream_data->id);
    data += variable_encode(data, stream_data->max);
    return data;
}

static const char* unpack_max_stream_data(const char* data, quic_max_stream_data* stream_data){
    data += variable_decode(data, &stream_data->id);
    data += variable_decode(data, &stream_data->max);
    return data;
}

static char* pack_stream_blocked(const quic_stream_blocked* blocked, char* data){
    data += variable_encode(data, blocked->id);
    data += variable_encode(data, blocked->size);
    return data;
}

static const char* unpack_stream_blocked(const char* data, quic_stream_blocked* blocked){
    data += variable_decode(data, &blocked->id);
    data += variable_decode(data, &blocked->size);
    return data;
}

void* pack_frame(void* buff, const quic_frame* frame) {
    size_t tlen = variable_encode(buff, frame->type);
    switch(frame->type){
    case QUIC_FRAME_PADDING:
        //padding frame must the last frame
        memset(buff, 0, frame->extra);
        return (char*)buff + frame->extra;
    case QUIC_FRAME_CRYPTO:
        return pack_crypto_frame(&frame->crypto, (char*)buff + tlen);
    case QUIC_FRAME_ACK:
        return pack_ack_frame(&frame->ack, (char*)buff + tlen);
    case QUIC_FRAME_ACK_ECN:
        return pack_ack_ecn_frame(&frame->ack, (char*)buff + tlen);
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return (char*) buff + tlen;
    case QUIC_FRAME_RESET_STREAM:
        return pack_reset_frame(&frame->reset, (char*)buff + tlen);
    case QUIC_FRAME_STOP_SENDING:
        return pack_stop_frame(&frame->stop, (char*)buff + tlen);
    case QUIC_FRAME_NEW_TOKEN:
        return pack_new_token_frame(&frame->new_token, (char*)buff + tlen);
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAMS_BI:
    case QUIC_FRAME_MAX_STREAMS_UBI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        return (char*)buff + tlen + variable_encode((char*)buff + tlen, frame->extra);
    case QUIC_FRAME_MAX_STREAM_DATA:
        return pack_max_stream_data(&frame->max_stream_data, (char*)buff + tlen);
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        return pack_stream_blocked(&frame->stream_blocked, (char*)buff + tlen);
    case QUIC_FRAME_NEW_CONNECTION_ID:
        return pack_new_id_frame(&frame->new_id, (char*)buff + tlen);
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        memcpy((char*)buff + tlen, frame->path_data, sizeof(frame->path_data));
        return (char*)buff + tlen + sizeof(frame->path_data);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return pack_close_frame(frame->type, &frame->close, (char*)buff + tlen);
    default:
        if((frame->type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame->type <= QUIC_FRAME_STREAM_END_ID))
        {
            return pack_stream_frame(frame->type, &frame->stream, (char*)buff + tlen);
        }else {
            LOGE("unknow frame: 0x%x\n", (int)frame->type);
            return nullptr;
        }
    }
}

int unpack_meta(const void* data_, size_t len, quic_meta* meta){
    const unsigned char* data = (const unsigned char*)data_;
    if(data[0]&0x80){
        //long packet
        meta->type = data[0] & 0x30;
        size_t pos = 1;
        meta->version = get32(data + pos);
        pos += 4;

        meta->dcid.resize(data[pos]);
        pos += 1;
        memcpy(&meta->dcid[0], data + pos, meta->dcid.length());
        pos += meta->dcid.length();

        meta->scid.resize(data[pos]);
        pos += 1;
        memcpy(&meta->scid[0], data + pos, meta->scid.length());
        pos += meta->scid.length();

        if(meta->type == QUIC_PACKET_INITIAL) {
            uint64_t token_len;
            pos += variable_decode(data + pos, &token_len);
            if (token_len > 0) {
                meta->token.resize(token_len);
                memcpy(&meta->token[0], data + pos, token_len);
                pos += token_len;
            }
        }
        if(meta->type != QUIC_PACKET_RETRY) {
            uint64_t payload_len;
            pos += variable_decode(data + pos, &payload_len);
            if (pos + payload_len > len) {
                LOGE("too short packet\n");
                return -1;
            }
            return (int) pos + (int) payload_len;
        }else{
            int token_len = len - pos - 16;
            if(token_len <= 0){
                LOGE("too short retry packet\n");
                return -1;
            }
            meta->token.resize(token_len);
            memcpy(&meta->token[0], data + pos, token_len);
            return (int)len;
        }
    }else{
        //short packet
        meta->type = QUIC_PACKET_1RTT;
        if(len <= meta->dcid.length() + 1){
            LOGE("too short packet\n");
            return -1;
        }
        memcpy(&meta->dcid[0], data+1, meta->dcid.length());
        return (int)len;
    }
}

const char* unpack_frame(const char* data, size_t len, quic_frame* frame){
    const char* pos = data + variable_decode(data, &frame->type);
    switch (frame->type) {
    case QUIC_FRAME_PADDING:
        //padding all the left
        frame->extra = len;
        return data + len;
    case QUIC_FRAME_CRYPTO:
        return unpack_crypto_frame(pos, &frame->crypto);
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return unpack_ack_frame(frame->type, pos, &frame->ack);
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return pos;
    case QUIC_FRAME_RESET_STREAM:
        return unpack_reset_frame(pos, &frame->reset);
    case QUIC_FRAME_STOP_SENDING:
        return unpack_stop_frame(pos, &frame->stop);
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAMS_BI:
    case QUIC_FRAME_MAX_STREAMS_UBI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        return pos + variable_decode(pos, &frame->extra);
    case QUIC_FRAME_MAX_STREAM_DATA:
        return unpack_max_stream_data(pos, &frame->max_stream_data);
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        return unpack_stream_blocked(pos, &frame->stream_blocked);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return unpack_close_frame(frame->type, pos, &frame->close);
    case QUIC_FRAME_NEW_CONNECTION_ID:
        return unpack_new_id_frame(pos, &frame->new_id);
    case QUIC_FRAME_NEW_TOKEN:
        return unpack_new_token_frame(pos, &frame->new_token);
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        memcpy(frame->path_data, pos, sizeof(frame->path_data));
        return pos + sizeof(frame->path_data);
    default:
        if((frame->type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame->type <= QUIC_FRAME_STREAM_END_ID))
        {
            return unpack_stream_frame(frame->type, pos, len, &frame->stream);
        }else {
            LOGE("unknow frame: 0x%x\n", (int)frame->type);
            return nullptr;
        }
    }
}

std::vector<quic_frame*> decode_packet(const void* data_, size_t len,
                                       quic_pkt_header* header, const quic_secret* secret){

    std::vector<quic_frame*> frames;
    const unsigned char* data = (const unsigned char*)data_;
    quic_meta& meta = header->meta;
    size_t pos = 0;
    unsigned char buff[1500];

    unsigned char mask[16];
    memset(mask, 0, 16);
    if(data[0]&0x80){
        //long packet
        pos = 7  + meta.dcid.length() + meta.scid.length();
        if(meta.type == QUIC_PACKET_INITIAL) {
            uint64_t token_len;
            pos += variable_decode(data + pos, &token_len);
            pos += token_len;
        }
        uint64_t payload_len;
        pos += variable_decode(data + pos, &payload_len);
        assert(len == pos + payload_len);

        if(hp_encode(secret->hcipher, (unsigned char*)secret->hp, (unsigned char*)data+pos+4, 16, mask) < 0){
            LOGE("aes_encode failed\n");
            return frames;
        }

        header->pn_length = ((data[0] ^ mask[0])&0x03) + 1;
        memcpy(buff, data, pos + header->pn_length);

        buff[0] ^= mask[0]&0x0f;
    }else{
        //short packet
        pos = 1 + meta.dcid.length();

        if(hp_encode(secret->hcipher, (unsigned char*)secret->hp, (unsigned char*)data+pos+4, 16, mask) < 0){
            LOGE("aes_encode failed\n");
            return frames;
        }

        header->pn_length = ((data[0] ^ mask[0])&0x03) + 1;
        memcpy(buff, data, pos + header->pn_length);

        buff[0] ^= mask[0]&0x1f;
    }


    header->pn = header->pn_acked & (0xffffffffffffffff << (header->pn_length*8));
    for(size_t i = 0; i < header->pn_length; i++){
        buff[pos+i] ^= mask[i+1];
        header->pn <<= 8;
        header->pn +=  buff[pos+i];
    }
    pos += header->pn_length;

    char iv[12];
    memcpy(iv, secret->iv, 12);
    for(int i = 0; i < 8; i++){
        iv[11-i] ^= (header->pn>>(i*8))&0xff;
    }

    int plantext_len = aead_decrypt(
            secret->cipher,
            (unsigned char*)data + pos,
            len - pos,
            buff,
            pos,
            (unsigned char*)secret->key,
            (unsigned char*)iv,
            buff + pos);
    if(plantext_len < 0){
        LOGE("gcm_decrypt error\n");
        return frames;
    }
    assert(plantext_len == (int)(len - pos -16));
    while(pos < len - 16){
        quic_frame* frame = new quic_frame;
        frame->type = QUIC_FRAME_PADDING;
        frames.push_back(frame);
        const char* ret = unpack_frame((const char*)buff + pos, len - pos, frame);
        if(ret == nullptr){
            goto error;
        }
        pos = (uchar*)ret - buff;
    }
    return frames;
error:
    for(auto frame: frames){
        frame_release(frame);
        delete frame;
    }
    frames.clear();
    return frames;
}


void frame_release(quic_frame* frame){
    switch(frame->type) {
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        delete []frame->ack.ranges;
        break;
    case QUIC_FRAME_CRYPTO:
        delete []frame->crypto.body;
        break;
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        delete []frame->close.reason;
        break;
    case QUIC_FRAME_NEW_CONNECTION_ID:
        delete []frame->new_id.id;
        break;
    case QUIC_FRAME_NEW_TOKEN:
        delete []frame->new_token.token;
        break;
    default:
        if((frame->type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame->type <= QUIC_FRAME_STREAM_END_ID))
        {
            delete []frame->stream.data;
        }
        break;
    }
}
