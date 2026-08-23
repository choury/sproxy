#include "quic_pack.h"
#include "prot/tls.h"
#include "misc/buffer.h"
#include "misc/config.h"
#include "misc/cert_manager.h"
#include "misc/defer.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <openssl/kdf.h>
#include <openssl/tls1.h>
#include <openssl/hmac.h>
#ifdef USE_BORINGSSL
#include <openssl/chacha.h>
#endif


/* 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
static const char* initial_salt = "\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
/* 0x0dede3def700a6db819381be6e269dcbf9bd2ed9 */
static const char* initial_saltv2 = "\x0d\xed\xe3\xde\xf7\x00\xa6\xdb\x81\x93\x81\xbe\x6e\x26\x9d\xcb\xf9\xbd\x2e\xd9";
static const int initial_saltlen = 20;

/* QUICv1 Retry Integrity Tag key and nonce */
static const char* retry_integrity_key_v1 = "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e";
static const char* retry_integrity_nonce_v1 = "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb";

/* QUICv2 Retry Integrity Tag key and nonce */
static const char* retry_integrity_key_v2 = "\x8f\xb4\xb0\x1b\x56\xac\x48\xe2\x60\xfb\xcb\xce\xad\x7c\xcc\x92";
static const char* retry_integrity_nonce_v2 = "\xd8\x69\x69\xbc\x2d\x7c\x6d\x99\x82\x88\x3d\xc8";

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

//返回varint占用的字节数(1/2/4/8)；pos==end时返回0
static size_t variable_decode_len(const void* pos_, const void* end){
    const unsigned char* pos = (const unsigned  char*)pos_;
    if(pos >= (const unsigned char*)end){
        return 0;
    }
    return 1 << (pos[0] >> 6);
}

std::optional<uint64_t> QuicCursor::variable_decode() const{
    size_t size = variable_decode_len(data(), data() + length());
    if(size == 0 || length() < size){
        return std::nullopt;
    }
    uint64_t value = data()[0] & 0x3fu;
    for(size_t i = 1; i < size; i ++){
        value = (value << 8) + data()[i];
    }
    advance(size);
    return value;
}

bool QuicCursor::variable_encode(uint64_t value){
    size_t size = variable_encode_len(value);
    if(size == 0 || length() < size){
        return false;
    }
    unsigned char* p = mutable_data();
    for(size_t i = 0; i < size; i++){
        p[i] = (unsigned char)(value >> (8 * (size - 1 - i)));
    }
    p[0] |= (unsigned char)(size == 2 ? 0x40 : size == 4 ? 0x80 : size == 8 ? 0xc0 : 0);
    advance(size);
    return true;
}

std::optional<uint64_t> QuicCursor::decode_long_packet(const quic_pkt_header* header) const{
    if(!advance(7 + header->dcid.length() + header->scid.length())){
        return std::nullopt;
    }
    if(header->type == QUIC_PACKET_INITIAL) {
        auto token_len = variable_decode();
        if(!token_len || token_len.value() > length()){
            return std::nullopt;
        }
        advance(token_len.value());
    }
    return variable_decode();
}

bool QuicCursor::decode_short_packet(const quic_pkt_header* header) const{
    return advance(1 + header->dcid.length());
}

//only used for initial key, so just use EVP_sha256
static int HKDF_Extract(const char* cid, size_t clen, char* prk, uint32_t version){
    size_t hashlen = EVP_MD_size(EVP_sha256());
    const char* salt = (version == QUIC_VERSION_2) ? initial_saltv2 : initial_salt;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const uint8_t*)salt, initial_saltlen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, (const uint8_t*)cid, clen) <= 0)
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

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, md) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, (const uint8_t*)prk, hashlen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, (const uint8_t*)label, labelLen) <= 0)
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

#ifdef USE_BORINGSSL
static int aead_encrypt(const EVP_AEAD* aead,
                       const cursor& plaintext,
                       const cursor& aad,
                       const unsigned char *key,
                       const unsigned char *iv,
                       cursor& ciphertext)
{
    if (!aead) {
        LOGE("aead_encrypt: aead is null\n");
        return -1;
    }
    if(ciphertext.length() < plaintext.length() + 16){
        LOGE("aead_encrypt: no space for ciphertext: %zd need %zd\n",
             ciphertext.length(), plaintext.length() + 16);
        return -1;
    }
    size_t len = SIZE_MAX;
    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH);
    defer(EVP_AEAD_CTX_free, ctx);
    if(!EVP_AEAD_CTX_init(ctx, aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)){
        LOGE("EVP_AEAD_CTX_init failed\n");
        return -1;
    }

    if(!EVP_AEAD_CTX_seal(ctx,
        ciphertext.mutable_data(), &len, len,
        iv, EVP_AEAD_nonce_length(aead),
        plaintext.data(), plaintext.length(),
        aad.data(), aad.length()))
    {
        LOGE("EVP_AEAD_CTX_seal failed\n");
        return -1;
    }
    ciphertext.advance(len);
    return len;
}

static int aead_decrypt(const EVP_AEAD* aead,
                          const cursor& ciphertext,
                          const cursor& aad,
                          unsigned char* key,
                          unsigned char* iv,
                          cursor& plaintext
) {
    if(ciphertext.length() < 16 || plaintext.length() + 16 < ciphertext.length()){
        LOGE("aead_decrypt: bad lengths: ct %zd, pt %zd\n",
             ciphertext.length(), plaintext.length());
        return -1;
    }
    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH);
    defer(EVP_AEAD_CTX_free, ctx);
    if(!EVP_AEAD_CTX_init(ctx, aead, key, EVP_AEAD_key_length(aead), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr)){
        LOGE("EVP_AEAD_CTX_init failed\n");
        return -1;
    }

    size_t len = 0;
    if(!EVP_AEAD_CTX_open(ctx,
        plaintext.mutable_data(), &len, ciphertext.length() - 16,
        iv, EVP_AEAD_nonce_length(aead),
        ciphertext.data(), ciphertext.length(),
        aad.data(), aad.length()))
    {
        LOGE("EVP_AEAD_CTX_open failed\n");
        return -1;
    }
    plaintext.advance(len);
    return len;
}

#else

static int aead_encrypt(const EVP_CIPHER* cipher,
                       const cursor& plaintext,
                       const cursor& aad,
                       const unsigned char *key,
                       const unsigned char *iv,
                       cursor& ciphertext)
{
    if(ciphertext.length() < plaintext.length() + 16){
        LOGE("aead_encrypt: no space for ciphertext: %zd need %zd\n",
             ciphertext.length(), plaintext.length() + 16);
        return -1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    /* Create and initialise the context */
    if(ctx == nullptr)
        return -1;
    defer(EVP_CIPHER_CTX_free, ctx);
    /* Initialise the encryption operation. */
    if(EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        LOGE("EVP_EncryptInit_ex failed\n");
        return -1;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        LOGE("EVP_CIPHER_Ctx_Ctrl IVLEN failed\n");
        return -1;
    }

    /* Initialise key and IV */
    if(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        LOGE("EVP_EncryptInit_ex failed\n");
        return -1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.length()) != 1) {
        LOGE("EVP_EncryptUpdate failed\n");
        return -1;
    }
    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(EVP_EncryptUpdate(ctx, ciphertext.mutable_data(), &len, plaintext.data(), plaintext.length()) != 1) {
        LOGE("EVP_EncryptUpdate failed\n");
        return -1;
    }
    ciphertext_len = len;
    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(EVP_EncryptFinal_ex(ctx, ciphertext.mutable_data() + ciphertext_len, &len) != 1) {
        LOGE("EVP_EncryptFinal_ex failed\n");
        return -1;
    }
    ciphertext_len += len;

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, ciphertext.mutable_data() + ciphertext_len) != 1) {
        LOGE("EVP_CIPHER_CTX_ctrl GET_TAG failed\n");
        return -1;
    }
    ciphertext_len += 16;
    ciphertext.advance(ciphertext_len);
    return ciphertext_len;
}


static int aead_decrypt(const EVP_CIPHER* cipher,
                       const cursor& ciphertext,
                       const cursor& aad,
                       unsigned char *key,
                       unsigned char *iv,
                       cursor& plaintext)
{
    if(ciphertext.length() < 16 || plaintext.length() + 16 < ciphertext.length()){
        LOGE("aead_decrypt: bad lengths: ct %zd, pt %zd\n",
             ciphertext.length(), plaintext.length());
        return -1;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    /* Create and initialise the context */
    if(ctx == nullptr) {
        LOGE("EVP_CIPHER_CTX_new failed\n");
        return -1;
    }
    defer(EVP_CIPHER_CTX_free, ctx);

    /* Initialise the decryption operation. */
    if(EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) {
        LOGE("EVP_DecryptInit_ex failed\n");
        return -1;
    }

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) {
        LOGE("EVP_CIPHER_Ctx_Ctrl IVLEN failed\n");
        return -1;
    }

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                           (void*)(ciphertext.data() + ciphertext.length() - 16)) != 1) {
        LOGE("EVP_CIPHER_CTX_ctrl SET_TAG failed\n");
        return -1;
    }

    /* Initialise key and IV */
    if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        LOGE("EVP_DecryptInit_ex failed\n");
        return -1;
    }

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.length()) != 1) {
        LOGE("EVP_DecryptUpdate failed\n");
        return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(EVP_DecryptUpdate(ctx, plaintext.mutable_data(), &len, ciphertext.data(), ciphertext.length() - 16) != 1) {
        LOGE("EVP_DecryptUpdate failed\n");
        return -1;
    }

    plaintext_len = len;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if(EVP_DecryptFinal_ex(ctx, plaintext.mutable_data() + len, &len) != 1) {
        LOGE("EVP_DecryptFinal_ex failed\n");
        return -1;
    }

    plaintext_len += len;
    plaintext.advance(plaintext_len);
    return plaintext_len;
}

#endif

//头部保护掩码：对sample游标处16字节采样加密得到掩码；采样不足16字节返回-1
static int hp_encode(const EVP_CIPHER* cipher,
                      const unsigned char* key,
                      const cursor& sample,
                      unsigned char* out)
{
    if(sample.length() < 16){
        LOGE("hp sample too short: %zd\n", sample.length());
        return -1;
    }
    const unsigned char* data = sample.data();
    if(cipher) {
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(ctx == nullptr)
            return -1;
        defer(EVP_CIPHER_CTX_free, ctx);
        if(EVP_EncryptInit_ex(ctx, cipher, nullptr, key, nullptr) != 1)
            return -1;

        if(EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
            return -1;

        int len;
        if(EVP_EncryptUpdate(ctx, out, &len, data, 16) != 1)
            return -1;
        int outlen = len;

        if(EVP_EncryptFinal_ex(ctx, out+outlen, &len) != 1)
            return -1;

        outlen += len;
        return outlen;
    } else {
        unsigned char _stub[5] = { 0, 0, 0, 0, 0, };
#ifdef USE_BORINGSSL
        const uint8_t *nonce;
        uint32_t counter;
#if __BYTE_ORDER == __LITTLE_ENDIAN
        memcpy(&counter, data, sizeof(counter));
#else
#error TODO: support non-little-endian machines
#endif
        nonce = data + sizeof(counter);
        CRYPTO_chacha_20(out, _stub, 5, key, nonce, counter);
#else
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if(ctx == nullptr)
            return -1;
        defer(EVP_CIPHER_CTX_free, ctx);
        if(EVP_EncryptInit_ex(ctx, EVP_chacha20(), nullptr, key, data) != 1)
            return -1;

        int len;
        if(EVP_EncryptUpdate(ctx, out, &len, _stub, sizeof(_stub)) != 1)
            return -1;
        int outlen = len;

        if(EVP_EncryptFinal_ex(ctx, out+outlen, &len) != 1)
            return -1;
#endif
        return 1;
    }
}

int quic_generate_initial_key(int client, const char* id, uint8_t id_len, struct quic_secret* secret, uint32_t version){
    char prk[32];
    if(HKDF_Extract(id, id_len, prk, version) < 0){
        LOGE("initial_secret failed: %.*s\n", id_len, id);
        return -1;
    }
#ifdef USE_BORINGSSL
    secret->cipher = EVP_aead_aes_128_gcm();
#else
    secret->cipher = EVP_aes_128_gcm();
#endif
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

    const char* key_label = (version == QUIC_VERSION_2) ? "quicv2 key" : "quic key";
    const char* iv_label = (version == QUIC_VERSION_2) ? "quicv2 iv" : "quic iv";
    const char* hp_label = (version == QUIC_VERSION_2) ? "quicv2 hp" : "quic hp";

    if(HKDF_Expand_Label(secret->md, initial_secret, key_label, "", secret->key, 16) < 0){
        LOGE("quic key failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, initial_secret, iv_label, "", secret->iv, 12) < 0){
        LOGE("quic iv failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, initial_secret, hp_label, "", secret->hp, 16) < 0){
        LOGE("quic hp failed\n");
        return -1;
    }
    return 0;
}

int quic_secret_set_key(struct quic_secret* secret, const char* key, uint32_t cipher, uint32_t version){
    size_t key_len;
    switch (cipher) {
    case TLS1_3_CK_AES_128_GCM_SHA256:
#ifdef USE_BORINGSSL
        secret->cipher = EVP_aead_aes_128_gcm();
#else
        secret->cipher = EVP_aes_128_gcm();
#endif
        secret->hcipher = EVP_aes_128_ecb();
        secret->md = EVP_sha256();
        break;
    case TLS1_3_CK_AES_256_GCM_SHA384:
#ifdef USE_BORINGSSL
        secret->cipher = EVP_aead_aes_256_gcm();
#else
        secret->cipher = EVP_aes_256_gcm();
#endif
        secret->hcipher = EVP_aes_256_ecb();
        secret->md = EVP_sha384();
        break;
    case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
#ifdef USE_BORINGSSL
        secret->cipher = EVP_aead_chacha20_poly1305();
#else
        secret->cipher = EVP_chacha20_poly1305();
#endif
        secret->hcipher = nullptr;
        secret->md = EVP_sha256();
        break;
    default:
        LOGE("unknown cipher: 0x%X\n", cipher);
        return -1;
    }
#ifdef USE_BORINGSSL
    key_len = EVP_AEAD_key_length(secret->cipher);
#else
    key_len = EVP_CIPHER_key_length(secret->cipher);
#endif
    const char* key_label = (version == QUIC_VERSION_2) ? "quicv2 key" : "quic key";
    const char* iv_label = (version == QUIC_VERSION_2) ? "quicv2 iv" : "quic iv";
    const char* hp_label = (version == QUIC_VERSION_2) ? "quicv2 hp" : "quic hp";

    if(HKDF_Expand_Label(secret->md, key, key_label, "", secret->key, key_len) < 0){
        LOGE("quic key failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, key, iv_label, "", secret->iv, 12) < 0){
        LOGE("quic iv failed\n");
        return -1;
    }
    if(HKDF_Expand_Label(secret->md, key, hp_label, "", secret->hp, key_len) < 0){
        LOGE("quic hp failed\n");
        return -1;
    }
    return 0;
}

//写出PN字段(pn_length字节)并推进游标；空间不足返回false
bool QuicCursor::put_pn(const quic_pkt_header* header){
    uint8_t pn_len = header->pn_length;
    assert(pn_len <= 4 && pn_len >=1);
    if(length() < pn_len){
        return false;
    }
    switch(pn_len) {
    case 1:
        mutable_data()[0] = header->pn & 0xff;
        break;
    case 2:
        set16(mutable_data(), header->pn & 0xffff);
        break;
    case 3:
        set24(mutable_data(), header->pn & 0xffffff);
        break;
    case 4:
        set32(mutable_data(), header->pn & 0xffffffff);
        break;
    default:
        abort();
    }
    advance(pn_len);
    return true;
}

bool QuicCursor::encode_short_packet(const quic_pkt_header* header){
    assert(header->pn_length >= 1 && header->pn_length <= 4);
    if(length() < 1){
        return false;
    }
    mutable_data()[0] = 0x40 | header->flags | (header->pn_length - 1);
    advance(1);
    if(!write_data(header->dcid.data(), header->dcid.length())){
        return false;
    }
    return put_pn(header);
}

bool QuicCursor::encode_long_packet(const quic_pkt_header* header, size_t payload_len){
    uint8_t pn_len = header->pn_length;
    assert(pn_len <= 4 && pn_len >=1);
    if(length() < 1){
        return false;
    }
    uint8_t wire_type = header->type;
    // Map standard types back to QUICv2 wire format
    if (header->version == QUIC_VERSION_2) {
        switch (header->type) {
        case QUIC_PACKET_RETRY:
            wire_type = QUIC_V2_RETRY_RAW;
            break;
        case QUIC_PACKET_INITIAL:
            wire_type = QUIC_V2_INITIAL_RAW;
            break;
        case QUIC_PACKET_0RTT:
            wire_type = QUIC_V2_0RTT_RAW;
            break;
        case QUIC_PACKET_HANDSHAKE:
            wire_type = QUIC_V2_HANDSHAKE_RAW;
            break;
        }
    }
    mutable_data()[0] = 0xc0 | wire_type | (pn_len - 1);
    advance(1);
    if(length() < 4){
        return false;
    }
    set32(mutable_data(), header->version ? header->version : QUIC_VERSION_1);
    advance(4);
    if(!variable_encode(header->dcid.length()) ||
       !write_data(header->dcid.data(), header->dcid.length()))
    {
        return false;
    }
    if(!variable_encode(header->scid.length()) ||
       !write_data(header->scid.data(), header->scid.length()))
    {
        return false;
    }
    if(header->type == QUIC_PACKET_INITIAL) {
        if(!variable_encode(header->token.length()) ||
           !write_data(header->token.data(), header->token.length()))
        {
            return false;
        }
    }
    if(!variable_encode(payload_len + pn_len)){
        return false;
    }
    return put_pn(header);
}


size_t encode_packet(cursor plaintext, const quic_pkt_header* header,
                     const quic_secret* secret, QuicCursor& out) {
    if (!secret || !secret->cipher) {
        LOGE("encode_packet: secret or secret->cipher is null\n");
        return 0;
    }

    //回借报文起点：AAD与HP定位需要已写区域，游标只前进，回借不属于游标操作
    unsigned char* base = out.mutable_data();
    const size_t cap = out.length();
    if(header->type == QUIC_PACKET_1RTT ? !out.encode_short_packet(header)
                                        : !out.encode_long_packet(header, plaintext.length() + 16)){
        LOGE("encode_packet: no space for header, cap: %zd\n", cap);
        return 0;
    }
    size_t header_len = cap - out.length();
    char iv[12];
    memcpy(iv, secret->iv, 12);
    for(int i = 0; i < 8; i++){
        iv[11-i] ^= (header->pn>>(i*8))&0xff;
    }
    size_t pn_length = (base[0] & 0x03) + 1;
    assert(pn_length == header->pn_length);

    cursor aad(base, header_len);
    int ciphertext_len = aead_encrypt(
            secret->cipher,
            plaintext,
            aad,
            (const unsigned char*)secret->key,
            (const unsigned char*)iv,
            out);
    if(ciphertext_len < 0){
        LOGE("gcm_encrypt error\n");
        return 0;
    }

    unsigned char mask[128];
    memset(mask, 0, 128);
    //PN字段是头部最后写出的内容，HP采样点固定为其后4字节起的16字节
    unsigned char* pn_pos = base + header_len - pn_length;
    if(hp_encode(secret->hcipher, (const unsigned char*)secret->hp, cursor(pn_pos + 4, 16), mask) < 0){
        LOGE("hp_encode failed\n");
        return 0;
    }
    base[0] ^= (base[0] & 0x80) ? (mask[0] & 0x0f) : (mask[0] & 0x1f);
    for(size_t i = 0; i < pn_length; i++){
        pn_pos[i] ^= mask[i + 1];
    }
    return header_len + ciphertext_len;
}

static size_t pack_crypto_frame_len(const struct quic_crypto* crypto){
    return variable_encode_len(crypto->offset) + variable_encode_len(crypto->length) + crypto->length;

}

static bool pack_crypto_frame(QuicCursor& c, const struct quic_crypto* crypto){
    return c.variable_encode(crypto->offset) &&
           c.variable_encode(crypto->length) &&
           c.write_data(crypto->buffer->data(), crypto->length);
}

//构造帧载荷Buffer：owner非空且len>0时切owner的零拷贝共享子区，否则完整拷贝
static Buffer* frame_payload(const Buffer* owner, const cursor& c, uint64_t len){
    if(owner && len){
        Buffer sub = *owner; //拷贝构造仅共享底层
        sub.reserve(c.data() - (const unsigned char*)owner->data());
        sub.truncate(len);
        return new Buffer(std::move(sub));
    }
    Buffer b(len);
    if(len){
        memcpy(b.mutable_data(), c.data(), len);
        b.truncate(len);
    }
    return new Buffer(std::move(b));
}

static bool unpack_crypto_frame(const QuicCursor& c, struct quic_crypto* crypto, const Buffer* owner){
    crypto->buffer = nullptr;
    auto offset = c.variable_decode();
    if(!offset){
        LOGE("crypto frame truncated: bad offset varint\n");
        return false;
    }
    crypto->offset = offset.value();
    auto length = c.variable_decode();
    if(!length){
        LOGE("crypto frame truncated: bad length varint\n");
        return false;
    }
    crypto->length = length.value();
    if(crypto->length > c.length()){
        LOGE("crypto frame truncated: length: %" PRIu64", remain: %zd\n",
             crypto->length, c.length());
        return false;
    }
    crypto->buffer = frame_payload(owner, c, crypto->length);
    c.advance(crypto->length);
    return true;
}

static size_t pack_ack_frame_len(uint64_t type, const struct quic_ack* ack) {
    size_t len = variable_encode_len(ack->acknowledged)
                 + variable_encode_len(ack->delay)
                 + variable_encode_len(ack->range_count)
                 + variable_encode_len(ack->first_range);
    for(size_t i = 0; i < ack->range_count; i++){
        len += variable_encode_len(ack->ranges[i].gap)
               + variable_encode_len(ack->ranges[i].length);
    }
    if(type == QUIC_FRAME_ACK_ECN){
        len += variable_encode_len(ack->ecn_ect0)
               + variable_encode_len(ack->ecn_ect1)
               + variable_encode_len(ack->ecn_ce);
    }
    return len;
}

static bool pack_ack_frame(QuicCursor& c, uint64_t type, const struct quic_ack* ack){
    if(!c.variable_encode(ack->acknowledged) ||
       !c.variable_encode(ack->delay) ||
       !c.variable_encode(ack->range_count) ||
       !c.variable_encode(ack->first_range))
    {
        return false;
    }
    for(size_t i = 0; i < ack->range_count; i++){
        if(!c.variable_encode(ack->ranges[i].gap) ||
           !c.variable_encode(ack->ranges[i].length))
        {
            return false;
        }
    }
    if(type == QUIC_FRAME_ACK_ECN){
        return c.variable_encode(ack->ecn_ect0) &&
               c.variable_encode(ack->ecn_ect1) &&
               c.variable_encode(ack->ecn_ce);
    }
    return true;
}

static bool unpack_ack_frame(const QuicCursor& c, uint64_t type, struct quic_ack* ack){
    assert(type == QUIC_FRAME_ACK || type == QUIC_FRAME_ACK_ECN);
    ack->ranges = nullptr;
    auto acknowledged = c.variable_decode();
    auto delay = c.variable_decode();
    auto range_count = c.variable_decode();
    auto first_range = c.variable_decode();
    if(!acknowledged || !delay || !range_count || !first_range){
        LOGE("ack frame truncated\n");
        return false;
    }
    ack->acknowledged = acknowledged.value();
    ack->delay = delay.value();
    ack->range_count = range_count.value();
    ack->first_range = first_range.value();
    // Each ack range consumes at least 2 bytes (gap + length varints), so a
    // range_count claiming more than half the remaining bytes is malformed.
    if(ack->range_count > c.length() / 2){
        LOGE("ack frame range_count too large: %" PRIu64", remain: %zd\n",
             ack->range_count, c.length());
        return false;
    }
    if(ack->range_count){
        ack->ranges = new quic_ack_range[ack->range_count];
        for(size_t i = 0 ; i < ack->range_count; i++){
            auto gap = c.variable_decode();
            auto length = c.variable_decode();
            if(!gap || !length){
                LOGE("ack frame range truncated\n");
                return false;
            }
            ack->ranges[i].gap = gap.value();
            ack->ranges[i].length = length.value();
        }
    }
    if(type == QUIC_FRAME_ACK_ECN){
        auto ect0 = c.variable_decode();
        auto ect1 = c.variable_decode();
        auto ce = c.variable_decode();
        if(!ect0 || !ect1 || !ce){
            LOGE("ack ecn frame truncated\n");
            return false;
        }
        ack->ecn_ect0 = ect0.value();
        ack->ecn_ect1 = ect1.value();
        ack->ecn_ce = ce.value();
    }else{
        ack->ecn_ect0 = 0;
        ack->ecn_ect1 = 0;
        ack->ecn_ce = 0;
    }
    return true;
}

static size_t pack_close_frame_len(uint64_t type, const struct quic_close* close_frame){
    size_t len = variable_encode_len(close_frame->error)
            + variable_encode_len(close_frame->reason_len)
            + close_frame->reason_len;
    if(type == QUIC_FRAME_CONNECTION_CLOSE){
        return len + variable_encode_len(close_frame->frame_type);
    }
    return len;
}

static bool pack_close_frame(QuicCursor& c, uint64_t type, const struct quic_close* close_frame){
    assert(type == QUIC_FRAME_CONNECTION_CLOSE || type == QUIC_FRAME_CONNECTION_CLOSE_APP);
    if(!c.variable_encode(close_frame->error)){
        return false;
    }
    if(type == QUIC_FRAME_CONNECTION_CLOSE){
        if(!c.variable_encode(close_frame->frame_type)){
            return false;
        }
    }
    return c.variable_encode(close_frame->reason_len) &&
           c.write_data(close_frame->reason, close_frame->reason_len);
}

static bool unpack_close_frame(const QuicCursor& c, uint64_t type, struct quic_close* close_frame){
    assert(type == QUIC_FRAME_CONNECTION_CLOSE || type == QUIC_FRAME_CONNECTION_CLOSE_APP);
    close_frame->reason = nullptr;
    auto error = c.variable_decode();
    if(!error){
        LOGE("close frame truncated: bad error varint\n");
        return false;
    }
    close_frame->error = error.value();
    if(type == QUIC_FRAME_CONNECTION_CLOSE_APP){
        close_frame->frame_type = QUIC_FRAME_PADDING;
    }else{
        auto frame_type = c.variable_decode();
        if(!frame_type){
            LOGE("close frame truncated: bad frame_type varint\n");
            return false;
        }
        close_frame->frame_type = frame_type.value();
    }
    auto reason_len = c.variable_decode();
    if(!reason_len){
        LOGE("close frame truncated: bad reason_len varint\n");
        return false;
    }
    close_frame->reason_len = reason_len.value();
    if(close_frame->reason_len > c.length()){
        LOGE("close frame reason truncated: %" PRIu64", remain: %zd\n",
             close_frame->reason_len, c.length());
        return false;
    }
    close_frame->reason = new char[close_frame->reason_len];
    memcpy(close_frame->reason, c.data(), close_frame->reason_len);
    c.advance(close_frame->reason_len);
    return true;
}

static size_t pack_new_id_frame_len(const struct quic_new_id* new_id){
    return variable_encode_len(new_id->seq)
           + variable_encode_len(new_id->retired)
           + 1 + new_id->length + sizeof(new_id->token);
}

static bool pack_new_id_frame(QuicCursor& c, const struct quic_new_id* new_id){
    return c.variable_encode(new_id->seq) &&
           c.variable_encode(new_id->retired) &&
           c.write<unsigned char>(new_id->length) &&
           c.write_data(new_id->id, new_id->length) &&
           c.write_data(new_id->token, sizeof(new_id->token));
}

static bool unpack_new_id_frame(const QuicCursor& c, struct quic_new_id* new_id){
    new_id->id = nullptr;
    auto seq = c.variable_decode();
    auto retired = c.variable_decode();
    if(!seq || !retired){
        LOGE("new connection id frame truncated: bad varint\n");
        return false;
    }
    new_id->seq = seq.value();
    new_id->retired = retired.value();
    if(c.empty()){
        return false;
    }
    new_id->length = *c.data();
    c.advance(1);
    if((uint64_t)new_id->length + sizeof(new_id->token) > c.length()){
        LOGE("new connection id frame truncated: length: %u, remain: %zd\n",
             new_id->length, c.length());
        return false;
    }
    new_id->id = new char[new_id->length];
    memcpy(new_id->id, c.data(), new_id->length);
    c.advance(new_id->length);
    memcpy(new_id->token, c.data(), sizeof(new_id->token));
    c.advance(sizeof(new_id->token));
    return true;
}

static size_t pack_new_token_frame_len(const quic_new_token* new_token){
    return variable_encode_len(new_token->length) + new_token->length;
}

static bool pack_new_token_frame(QuicCursor& c, const quic_new_token* new_token){
    return c.variable_encode(new_token->length) &&
           c.write_data(new_token->token, new_token->length);
}

static bool unpack_new_token_frame(const QuicCursor& c, struct quic_new_token* new_token){
    new_token->token = nullptr;
    auto length = c.variable_decode();
    if(!length){
        LOGE("new token frame truncated: bad length varint\n");
        return false;
    }
    new_token->length = length.value();
    if(new_token->length > c.length()){
        LOGE("new token frame truncated: length: %" PRIu64", remain: %zd\n",
             new_token->length, c.length());
        return false;
    }
    new_token->token = new char[new_token->length];
    memcpy(new_token->token, c.data(), new_token->length);
    c.advance(new_token->length);
    return true;
}

static size_t pack_stream_frame_len(uint64_t type, const quic_stream* stream){
    size_t len = variable_encode_len(stream->id) + stream->length;
    if(type & QUIC_FRAME_STREAM_OFF_F){
        len += variable_encode_len(stream->offset);
    }
    if(type & QUIC_FRAME_STREAM_LEN_F){
        len += variable_encode_len(stream->length);
    }
    return len;
}

static bool pack_stream_frame(QuicCursor& c, uint64_t type, const quic_stream* stream){
    assert((type >= QUIC_FRAME_STREAM_START_ID)
        && (type <= QUIC_FRAME_STREAM_END_ID));
    if(!c.variable_encode(stream->id)){
        return false;
    }
    if(type & QUIC_FRAME_STREAM_OFF_F){
        if(!c.variable_encode(stream->offset)){
            return false;
        }
    }
    if(type & QUIC_FRAME_STREAM_LEN_F){
        if(!c.variable_encode(stream->length)){
            return false;
        }
    }
    return c.write_data(stream->buffer->data(), stream->length);
}

static bool unpack_stream_frame(const QuicCursor& c, uint64_t type, quic_stream* stream, const Buffer* owner) {
    auto id = c.variable_decode();
    if(!id){
        LOGE("stream frame truncated: bad id varint\n");
        return false;
    }
    stream->id = id.value();
    if(type & QUIC_FRAME_STREAM_OFF_F){
        auto offset = c.variable_decode();
        if(!offset){
            LOGE("stream frame truncated: bad offset varint\n");
            return false;
        }
        stream->offset = offset.value();
    }else{
        stream->offset = 0;
    }
    if(type & QUIC_FRAME_STREAM_LEN_F){
        auto length = c.variable_decode();
        if(!length){
            LOGE("stream frame truncated: bad length varint\n");
            return false;
        }
        stream->length = length.value();
    }else{
        stream->length = c.length();
    }
    if(stream->length > c.length()){
        LOGE("stream frame truncated: length: %" PRIu64", remain: %zd\n",
             stream->length, c.length());
        return false;
    }

    stream->buffer = frame_payload(owner, c, stream->length);
    c.advance(stream->length);
    return true;
}

static size_t pack_reset_frame_len(const quic_reset* reset){
    return variable_encode_len(reset->id)
    + variable_encode_len(reset->error)
    + variable_encode_len(reset->fsize);
}

static bool pack_reset_frame(QuicCursor& c, const quic_reset* reset){
    return c.variable_encode(reset->id) &&
           c.variable_encode(reset->error) &&
           c.variable_encode(reset->fsize);
}

static bool unpack_reset_frame(const QuicCursor& c, quic_reset* reset){
    auto id = c.variable_decode();
    auto error = c.variable_decode();
    auto fsize = c.variable_decode();
    if(!id || !error || !fsize){
        LOGE("reset stream frame truncated\n");
        return false;
    }
    reset->id = id.value();
    reset->error = error.value();
    reset->fsize = fsize.value();
    return true;
}

static size_t pack_stop_frame_len(const quic_stop* stop) {
    return variable_encode_len(stop->id) + variable_encode_len(stop->error);
}

static bool pack_stop_frame(QuicCursor& c, const quic_stop* stop){
    return c.variable_encode(stop->id) &&
           c.variable_encode(stop->error);
}

static bool unpack_stop_frame(const QuicCursor& c, quic_stop* stop){
    auto id = c.variable_decode();
    auto error = c.variable_decode();
    if(!id || !error){
        LOGE("stop sending frame truncated\n");
        return false;
    }
    stop->id = id.value();
    stop->error = error.value();
    return true;
}

static size_t pack_max_stream_data_len(const quic_max_stream_data* stream_data){
    return variable_encode_len(stream_data->id) + variable_encode_len(stream_data->max);
}

static bool pack_max_stream_data(QuicCursor& c, const quic_max_stream_data* stream_data){
    return c.variable_encode(stream_data->id) &&
           c.variable_encode(stream_data->max);
}

static bool unpack_max_stream_data(const QuicCursor& c, quic_max_stream_data* stream_data){
    auto id = c.variable_decode();
    auto max = c.variable_decode();
    if(!id || !max){
        LOGE("max stream data frame truncated\n");
        return false;
    }
    stream_data->id = id.value();
    stream_data->max = max.value();
    return true;
}

static size_t pack_stream_blocked_len(const quic_stream_data_blocked* blocked) {
    return variable_encode_len(blocked->id) + variable_encode_len(blocked->size);
}

static bool pack_stream_blocked(QuicCursor& c, const quic_stream_data_blocked* blocked){
    return c.variable_encode(blocked->id) &&
           c.variable_encode(blocked->size);
}

static bool unpack_stream_blocked(const QuicCursor& c, quic_stream_data_blocked* blocked){
    auto id = c.variable_decode();
    auto size = c.variable_decode();
    if(!id || !size){
        LOGE("stream data blocked frame truncated\n");
        return false;
    }
    blocked->id = id.value();
    blocked->size = size.value();
    return true;
}

static size_t pack_datagram_frame_len(uint64_t type, const quic_datagram* datagram){
    size_t len = datagram->length;
    if(type == QUIC_FRAME_DATAGRAM_LEN){
        len += variable_encode_len(datagram->length);
    }
    return len;
}

static bool pack_datagram_frame(QuicCursor& c, uint64_t type, const quic_datagram* datagram){
    if(type == QUIC_FRAME_DATAGRAM_LEN){
        if(!c.variable_encode(datagram->length)){
            return false;
        }
    }
    return c.write_data(datagram->buffer->data(), datagram->length);
}

static bool unpack_datagram_frame(const QuicCursor& c, uint64_t type, quic_datagram* datagram, const Buffer* owner){
    if(type == QUIC_FRAME_DATAGRAM_LEN){
        auto length = c.variable_decode();
        if(!length){
            LOGE("datagram frame truncated: bad length varint\n");
            return false;
        }
        datagram->length = length.value();
    }else{
        datagram->length = c.length();
    }
    if(datagram->length > c.length()){
        LOGE("datagram frame truncated: length: %" PRIu64", remain: %zd\n",
             datagram->length, c.length());
        return false;
    }

    datagram->buffer = frame_payload(owner, c, datagram->length);
    c.advance(datagram->length);
    return true;
}

size_t pack_frame_len(const quic_frame& frame){
    size_t tlen = variable_encode_len(frame.type);
    switch(frame.type){
    case QUIC_FRAME_PADDING:
        return frame.extra;
    case QUIC_FRAME_CRYPTO:
        return tlen + pack_crypto_frame_len(&frame.crypto);
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return tlen + pack_ack_frame_len(frame.type, &frame.ack);
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return tlen;
    case QUIC_FRAME_RESET_STREAM:
        return tlen + pack_reset_frame_len(&frame.reset);
    case QUIC_FRAME_STOP_SENDING:
        return tlen + pack_stop_frame_len(&frame.stop);
    case QUIC_FRAME_NEW_TOKEN:
        return tlen + pack_new_token_frame_len(&frame.new_token);
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAMS_BI:
    case QUIC_FRAME_MAX_STREAMS_UBI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        return tlen + variable_encode_len(frame.extra);
    case QUIC_FRAME_MAX_STREAM_DATA:
        return tlen + pack_max_stream_data_len(&frame.max_stream_data);
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        return tlen + pack_stream_blocked_len(&frame.stream_data_blocked);
    case QUIC_FRAME_NEW_CONNECTION_ID:
        return tlen + pack_new_id_frame_len(&frame.new_id);
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        return tlen + sizeof(frame.path_data);
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return tlen + pack_close_frame_len(frame.type, &frame.close);
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        return tlen + pack_datagram_frame_len(frame.type, &frame.datagram);
    default:
        if((frame.type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame.type <= QUIC_FRAME_STREAM_END_ID))
        {
            return tlen + pack_stream_frame_len(frame.type, &frame.stream);
        }else {
            LOGE("unknown frame: 0x%x\n", (int)frame.type);
            return 0;
        }
    }
}

bool QuicCursor::put_frame(const quic_frame& frame) {
    if(!variable_encode(frame.type)){
        return false;
    }
    switch(frame.type){
    case QUIC_FRAME_PADDING:
        //type字节本身为0，剩余extra-1字节补0，总长与pack_frame_len一致
        if(frame.extra > 1){
            if(length() < frame.extra - 1){
                return false;
            }
            memset(mutable_data(), 0, frame.extra - 1);
            advance(frame.extra - 1);
        }
        return true;
    case QUIC_FRAME_CRYPTO:
        return pack_crypto_frame(*this, &frame.crypto);
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        return pack_ack_frame(*this, frame.type, &frame.ack);
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return true;
    case QUIC_FRAME_RESET_STREAM:
        return pack_reset_frame(*this, &frame.reset);
    case QUIC_FRAME_STOP_SENDING:
        return pack_stop_frame(*this, &frame.stop);
    case QUIC_FRAME_NEW_TOKEN:
        return pack_new_token_frame(*this, &frame.new_token);
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAMS_BI:
    case QUIC_FRAME_MAX_STREAMS_UBI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        return variable_encode(frame.extra);
    case QUIC_FRAME_MAX_STREAM_DATA:
        return pack_max_stream_data(*this, &frame.max_stream_data);
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        return pack_stream_blocked(*this, &frame.stream_data_blocked);
    case QUIC_FRAME_NEW_CONNECTION_ID:
        return pack_new_id_frame(*this, &frame.new_id);
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        return write_data(frame.path_data, sizeof(frame.path_data));
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return pack_close_frame(*this, frame.type, &frame.close);
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        return pack_datagram_frame(*this, frame.type, &frame.datagram);
    default:
        if((frame.type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame.type <= QUIC_FRAME_STREAM_END_ID))
        {
            return pack_stream_frame(*this, frame.type, &frame.stream);
        }else {
            LOGE("unknown frame: 0x%x\n", (int)frame.type);
            return false;
        }
    }
}

//解析QUIC报文头元信息；成功返回meta且pkt推进到本包末尾(合并包循环即while(pkt.length()))
//短包的dcid长度不在线路上携带，由dcid_len给出；长包忽略该参数
std::optional<quic_meta> unpack_meta(const QuicCursor& pkt, size_t dcid_len){
    const size_t len = pkt.length();
    if(pkt.length() == 0){
        LOGE("empty quic packet\n");
        return std::nullopt;
    }
    quic_meta meta;
    unsigned char flags = *pkt.data();
    meta.flags = flags;
    if((flags & 0x40) == 0){
        LOGE("unsupported quic version: 0x%02x\n", flags);
        return std::nullopt;
    }
    if(flags & 0x80){
        //long packet
        if(!pkt.advance(1) || pkt.length() < 6){ //version + dcid/scid长度字节
            LOGE("too short long packet, len: %zd\n", len);
            return std::nullopt;
        }
        uint8_t raw_type = flags & 0x30;
        meta.version = get32(pkt.data());
        if(meta.version != QUIC_VERSION_1 && meta.version != QUIC_VERSION_2){
            LOGE("unsupported version: 0x%X\n", meta.version);
            return std::nullopt;
        }

        // Map QUICv2 packet types to standard types
        if (meta.version == QUIC_VERSION_2) {
            switch (raw_type) {
            case QUIC_V2_RETRY_RAW:
                meta.type = QUIC_PACKET_RETRY;
                break;
            case QUIC_V2_INITIAL_RAW:
                meta.type = QUIC_PACKET_INITIAL;
                break;
            case QUIC_V2_0RTT_RAW:
                meta.type = QUIC_PACKET_0RTT;
                break;
            case QUIC_V2_HANDSHAKE_RAW:
                meta.type = QUIC_PACKET_HANDSHAKE;
                break;
            default:
                LOGE("unknown QUICv2 packet type: 0x%02x\n", raw_type);
                return std::nullopt;
            }
        } else {
            meta.type = raw_type;
        }
        pkt.advance(4);

        size_t dlen = *pkt.data();
        pkt.advance(1);
        //dcid之后必须还有scid长度字节，否则下面的读取越界
        if(pkt.length() < dlen + 1){
            LOGE("too short packet for dcid, len: %zd, pos: %zd, dcid: %zd\n",
                 len, len - pkt.length(), dlen);
            return std::nullopt;
        }
        meta.dcid.assign((const char*)pkt.data(), dlen);
        pkt.advance(dlen);

        size_t slen = *pkt.data();
        pkt.advance(1);
        if(slen > pkt.length()){
            LOGE("too short packet for scid, len: %zd, pos: %zd, scid: %zd\n",
                 len, len - pkt.length(), slen);
            return std::nullopt;
        }
        meta.scid.assign((const char*)pkt.data(), slen);
        pkt.advance(slen);

        if(meta.type == QUIC_PACKET_INITIAL) {
            auto token_len = pkt.variable_decode();
            if(!token_len){
                LOGE("too short packet for token length, len: %zd, pos: %zd\n",
                     len, len - pkt.length());
                return std::nullopt;
            }
            if(token_len.value() > pkt.length()){
                LOGE("too short packet, token: %" PRIu64", remain: %zd\n",
                     token_len.value(), pkt.length());
                return std::nullopt;
            }
            meta.token.assign((const char*)pkt.data(), token_len.value());
            pkt.advance(token_len.value());
        }
        if(meta.type != QUIC_PACKET_RETRY) {
            auto payload_len = pkt.variable_decode();
            if(!payload_len){
                LOGE("too short packet for payload length, len: %zd, pos: %zd\n",
                     len, len - pkt.length());
                return std::nullopt;
            }
            if(payload_len.value() > pkt.length()){
                LOGE("too short packet, type:%x, payload: %zd, len: %zd\n",
                     meta.type, (size_t)(len - pkt.length() + payload_len.value()), len);
                return std::nullopt;
            }
            //本包长度 = 已消费的头部 + payload；游标推进到包尾(合并包循环)
            pkt.advance(payload_len.value());
        }else{
            //retry packet
            if(pkt.length() <= 16){
                LOGE("too short retry packet, len: %zd, pos: %zd\n", len, len - pkt.length());
                return std::nullopt;
            }
            meta.token.assign((const char*)pkt.data(), pkt.length() - 16);
            //retry包占满剩余数据报
            pkt.advance(pkt.length());
        }
    }else{
        //short packet：dcid长度不在线路上携带，由dcid_len给出
        meta.type = QUIC_PACKET_1RTT;
        pkt.advance(1);
        if(pkt.length() <= dcid_len){
            LOGE("too short packet, len:%zd, id len: %zd\n", len, dcid_len);
            return std::nullopt;
        }
        meta.dcid.assign((const char*)pkt.data(), dcid_len);
        //短包总是占满剩余数据报(RFC 9000 §17.3)
        pkt.advance(pkt.length());
    }
    return meta;
}

std::optional<quic_frame> QuicCursor::get_frame(const Buffer* owner) const{
    auto type = variable_decode();
    if(!type){
        LOGE("frame truncated: bad type varint, remain: %zd\n", length());
        return std::nullopt;
    }
    quic_frame frame{type.value()};
    switch (frame.type) {
    case QUIC_FRAME_PADDING:
        frame.extra = 1;
        while(length() && *data() == 0){
            advance(1);
            frame.extra++;
        }
        return frame;
    case QUIC_FRAME_CRYPTO:
        if(!unpack_crypto_frame(*this, &frame.crypto, owner)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        if(!unpack_ack_frame(*this, frame.type, &frame.ack)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_PING:
    case QUIC_FRAME_HANDSHAKE_DONE:
        return frame;
    case QUIC_FRAME_RESET_STREAM:
        if(!unpack_reset_frame(*this, &frame.reset)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_STOP_SENDING:
        if(!unpack_stop_frame(*this, &frame.stop)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_MAX_DATA:
    case QUIC_FRAME_MAX_STREAMS_BI:
    case QUIC_FRAME_MAX_STREAMS_UBI:
    case QUIC_FRAME_DATA_BLOCKED:
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
    case QUIC_FRAME_RETIRE_CONNECTION_ID: {
        auto extra = variable_decode();
        if(!extra){
            LOGE("frame truncated: bad extra varint\n");
            return std::nullopt;
        }
        frame.extra = extra.value();
        return frame;
    }
    case QUIC_FRAME_MAX_STREAM_DATA:
        if(!unpack_max_stream_data(*this, &frame.max_stream_data)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        if(!unpack_stream_blocked(*this, &frame.stream_data_blocked)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        if(!unpack_close_frame(*this, frame.type, &frame.close)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_NEW_CONNECTION_ID:
        if(!unpack_new_id_frame(*this, &frame.new_id)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_NEW_TOKEN:
        if(!unpack_new_token_frame(*this, &frame.new_token)){
            return std::nullopt;
        }
        return frame;
    case QUIC_FRAME_PATH_CHALLENGE:
    case QUIC_FRAME_PATH_RESPONSE:
        if(length() < sizeof(frame.path_data)){
            LOGE("too short path frame, remain: %zd\n", length());
            return std::nullopt;
        }
        memcpy(frame.path_data, data(), sizeof(frame.path_data));
        advance(sizeof(frame.path_data));
        return frame;
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        if(!unpack_datagram_frame(*this, frame.type, &frame.datagram, owner)){
            return std::nullopt;
        }
        return frame;
    default:
        if((frame.type >= QUIC_FRAME_STREAM_START_ID)
           && (frame.type <= QUIC_FRAME_STREAM_END_ID))
        {
            if(!unpack_stream_frame(*this, frame.type, &frame.stream, owner)){
                return std::nullopt;
            }
            return frame;
        }else {
            LOGE("unknown frame: 0x%x\n", (int)frame.type);
            return std::nullopt;
        }
    }
}

static uint64_t decode_pn(uint64_t expected_pn, uint64_t truncated_pn, int pn_nbits) {
   uint64_t pn_win       = 1ull << pn_nbits;
   uint64_t pn_hwin      = pn_win / 2;
   uint64_t pn_mask      = pn_win - 1;
   // The incoming packet number should be greater than
   // expected_pn - pn_hwin and less than or equal to
   // expected_pn + pn_hwin
   //
   // This means we cannot just strip the trailing bits from
   // expected_pn and add the truncated_pn because that might
   // yield a value outside the window.
   //
   // The following code calculates a candidate value and
   // makes sure it's within the packet number window.
   // Note the extra checks to prevent overflow and underflow.
   uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
   if (candidate_pn + pn_hwin <= expected_pn && candidate_pn + pn_win < (1ull << 62)){
      return candidate_pn + pn_win;
   }
   if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win){
      return candidate_pn - pn_win;
   }
   return candidate_pn;
}

//去掉首字节与PN字段的头部保护并解码PN；成功时pkt推进到密文起点
//失败即报文不可解(头畸形/采样不足)：调用方应静默丢弃
static bool unprotect(QuicCursor& pkt, quic_pkt_header* header, const quic_secret* secret){
    unsigned char* data = pkt.mutable_data();
    const size_t len = pkt.length();
    unsigned char flags = *pkt.data();
    unsigned char mask[16];
    memset(mask, 0, 16);
    size_t pos = 0; //头部(含PN)长度
    if(flags & 0x80){
        //long packet
        auto payload = pkt.decode_long_packet(header);
        if(!payload){
            LOGE("QUIC long packet header truncated, len: %zd\n", len);
            return false;
        }
        uint64_t payload_len = payload.value();
        size_t hlen = len - pkt.length(); //头部(不含PN)长度
        if(len != hlen + payload_len){
            LOGE("QUIC packet length mismatch: len: %zd, pos: %zd, payload_len: %" PRIu64"\n",
                 len, hlen, payload_len);
            return false;
        }
        //payload must hold the 4-byte sample of header protection plus the
        //16-byte AEAD tag; the exact pn_length is checked again once decoded
        if(payload_len < 4 + 16){
            LOGE("QUIC packet payload too small: %" PRIu64"\n", payload_len);
            return false;
        }

        //HP采样点固定在PN字段后4字节起的16字节
        if(hp_encode(secret->hcipher, (const unsigned char*)secret->hp, cursor(data + hlen + 4, 16), mask) < 0){
            LOGE("hp_encode failed\n");
            return false;
        }

        header->pn_length = ((flags ^ mask[0])&0x03) + 1;
        if(payload_len < header->pn_length + 16){
            LOGE("QUIC packet payload too small: %" PRIu64", pn_len: %zd\n",
                 payload_len, header->pn_length);
            return false;
        }
        //原地解掩码：首字节与PN字段
        data[0] ^= mask[0]&0x0f;
        pos = hlen;
    }else{
        //short packet
        if(!pkt.decode_short_packet(header)){
            LOGE("QUIC short packet too small: len: %zd\n", len);
            return false;
        }
        size_t hlen = len - pkt.length();
        if(pkt.length() < 4 + 16){
            LOGE("QUIC short packet too small: len: %zd, pos: %zd\n", len, hlen);
            return false;
        }

        if(hp_encode(secret->hcipher, (const unsigned char*)secret->hp, cursor(data + hlen + 4, 16), mask) < 0){
            LOGE("hp_encode failed\n");
            return false;
        }

        header->pn_length = ((flags ^ mask[0])&0x03) + 1;
        if(pkt.length() < header->pn_length + 16){
            LOGE("QUIC short packet too small: len: %zd, pos: %zd, pn_len: %zd\n",
                 len, hlen, header->pn_length);
            return false;
        }
        data[0] ^= mask[0]&0x1f;
        pos = hlen;
    }

    uint64_t pn = 0;
    for(size_t i = 0; i < header->pn_length; i++){
        data[pos+i] ^= mask[i+1];
        pn <<= 8;
        pn +=  data[pos+i];
    }
    header->pn = decode_pn(header->pn_base, pn, header->pn_length*8);
    pkt.advance(header->pn_length); //剩余部分即密文+tag
    return true;
}

quic_decode_status decode_packet(Buffer pkt, quic_pkt_header* header,
                                 const quic_secret* secret,
                                 std::deque<quic_frame>* out){
    if(pkt.len == 0){
        return quic_decode_status::drop;
    }
    //独占时原地解密；共享时此处自动COW分裂(见misc/buffer.h)
    unsigned char* data = (unsigned char*)pkt.mutable_data();
    const size_t len = pkt.len;
    QuicCursor pktc(data, len);

    //第一段：去头部保护(含PN解码)；pktc推进到密文起点
    if(!unprotect(pktc, header, secret)){
        return quic_decode_status::drop;
    }
    const size_t pos = len - pktc.length() - header->pn_length; //头部(不含PN)长度
    assert(pos + header->pn_length == (size_t)(pktc.data() - data));

    //第二段：AEAD解密。AAD = 已解掩码的头部(含明文PN)，明文原地写回密文位置
    char iv[12];
    memcpy(iv, secret->iv, 12);
    for(int i = 0; i < 8; i++){
        iv[11-i] ^= (header->pn>>(i*8))&0xff;
    }
    cursor aad(data, pos + header->pn_length);
    cursor plain(data + pos + header->pn_length, len - pos - header->pn_length);
    int plaintext_len = aead_decrypt(
            secret->cipher,
            pktc,
            aad,
            (unsigned char*)secret->key,
            (unsigned char*)iv,
            plain);
    if(plaintext_len < 0){
        LOGE("gcm_decrypt error, pn: %d, len: %zd\n", (int)header->pn, len);
        return quic_decode_status::drop;
    }
    assert(plaintext_len == (int)(len - pos - header->pn_length - 16));

    //第三段：帧循环，载荷零拷贝共享pkt
    QuicCursor fc(data + pos + header->pn_length, plaintext_len);
    while(fc.length()){
        auto frame = fc.get_frame(&pkt);
        if(!frame){
            //AEAD已通过：明文由对端认证，畸形帧按RFC 9000应断连而非静默丢弃
            out->clear();
            return quic_decode_status::conn_error;
        }
        out->push_back(std::move(*frame));
    }
    return quic_decode_status::ok;
}

bool is_ack_eliciting(const quic_frame& frame){
    switch(frame.type){
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
    case QUIC_FRAME_PADDING:
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        return false;
    default:
        return true;
    }
}

void dumpFrame(const char* prefix, char name, const quic_frame& frame) {
    switch (frame.type) {
    case QUIC_FRAME_PADDING:
        LOGD(DQUIC, "%s [%c] padding frame: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_PING:
        LOGD(DQUIC, "%s [%c] ping frame\n", prefix, name);
        return;
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN: {
        const quic_ack* ack = &frame.ack;
        uint64_t pos = ack->acknowledged - ack->first_range;
        LOGD(DQUIC, "%s [%c] ack frame %" PRIu64" - %" PRIu64", delay: %" PRIu64"\n", prefix, name,
             pos, ack->acknowledged, frame.ack.delay);
        for(size_t i = 0; i < ack->range_count; i++){
            pos -= 2;
            LOGD(DQUIC, "\trange: %" PRIu64" - %" PRIu64"\n",
                 pos - ack->ranges[i].gap - ack->ranges[i].length, pos - ack->ranges[i].gap);
            pos -= ack->ranges[i].gap + ack->ranges[i].length;
        }
        return;
    }
    case QUIC_FRAME_RESET_STREAM:
        LOGD(DQUIC, "%s [%c] reset stream: %" PRIu64", error: %" PRIu64", finSize: %" PRIu64"\n", prefix, name,
             frame.reset.id, frame.reset.error, frame.reset.fsize);
        return;
    case QUIC_FRAME_STOP_SENDING:
        LOGD(DQUIC, "%s [%c] stop stream: %" PRIu64", error: %" PRIu64"\n", prefix, name,
             frame.stop.id, frame.stop.error);
        return;
    case QUIC_FRAME_CRYPTO:
        LOGD(DQUIC, "%s [%c] crypto frame: %" PRIu64" - %" PRIu64"\n", prefix, name,
             frame.crypto.offset, frame.crypto.offset + frame.crypto.length);
        return;
    case QUIC_FRAME_NEW_TOKEN:
        LOGD(DQUIC, "%s [%c] new token: %s\n", prefix, name,
             dumpHex(frame.new_token.token, frame.new_token.length).c_str());
        return;
    /*skip stream frame here*/
    case QUIC_FRAME_MAX_DATA:
        LOGD(DQUIC, "%s [%c] max data: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_MAX_STREAM_DATA:
        LOGD(DQUIC, "%s [%c] max stream data: %" PRIu64", size: %" PRIu64"\n", prefix, name,
             frame.max_stream_data.id, frame.max_stream_data.max);
        return;
    case QUIC_FRAME_MAX_STREAMS_BI:
        LOGD(DQUIC, "%s [%c] max stream_bi: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_MAX_STREAMS_UBI:
        LOGD(DQUIC, "%s [%c] max stream_ubi: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_DATA_BLOCKED:
        LOGD(DQUIC, "%s [%c] blocked data size: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_STREAM_DATA_BLOCKED:
        LOGD(DQUIC, "%s [%c] blocked stream data: %" PRIu64", size: %" PRIu64"\n", prefix, name,
             frame.stream_data_blocked.id, frame.stream_data_blocked.size);
        return;
    case QUIC_FRAME_STREAMS_BLOCKED_BI:
        LOGD(DQUIC, "%s [%c] blocked stream_bi: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_STREAMS_BLOCKED_UBI:
        LOGD(DQUIC, "%s [%c] blocked stream_ubi: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_NEW_CONNECTION_ID:
        LOGD(DQUIC, "%s [%c] new connection id seq:%" PRIu64", retired:%" PRIu64", id:%s, token:%s\n", prefix, name,
             frame.new_id.seq, frame.new_id.retired,
             dumpHex(frame.new_id.id, frame.new_id.length).c_str(),
             dumpHex(frame.new_id.token, 16).c_str());
        return;
    case QUIC_FRAME_RETIRE_CONNECTION_ID:
        LOGD(DQUIC, "%s [%c] retire connection id: %" PRIu64"\n", prefix, name, frame.extra);
        return;
    case QUIC_FRAME_PATH_CHALLENGE:
        LOGD(DQUIC, "%s [%c] path challenge: %s\n", prefix, name,
             dumpHex(frame.path_data, sizeof(frame.path_data)).c_str());
        return;
    case QUIC_FRAME_PATH_RESPONSE:
        LOGD(DQUIC, "%s [%c] path response: %s\n", prefix, name,
            dumpHex(frame.path_data, sizeof(frame.path_data)).c_str());
        return;
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        LOGD(DQUIC, "%s [%c] close frame: %" PRIu64 ": %.*s\n", prefix, name,
             frame.close.error, (int)frame.close.reason_len, frame.close.reason);
        return;
    case QUIC_FRAME_HANDSHAKE_DONE:
        LOGD(DQUIC, "%s [%c] handshake_done frame\n", prefix, name);
        return;
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        LOGD(DQUIC, "%s [%c] datagram frame: %" PRIu64" bytes\n", prefix, name, frame.datagram.length);
        return;
    default:
        if (frame.type >= QUIC_FRAME_STREAM_START_ID && frame.type <= QUIC_FRAME_STREAM_END_ID) {
            LOGD(DQUIC, "%s [%c] data [%" PRIu64"]: %" PRIu64" - %" PRIu64"\n", prefix, name,
                 frame.stream.id, frame.stream.offset, frame.stream.offset + frame.stream.length);
            return;
        } else {
            LOGD(DQUIC, "%s [%c] ignore frame: 0x%02x\n", prefix, name, (int) frame.type);
        }
        return;
    }
}

size_t frame_size(const quic_frame& frame) {
    size_t usage = sizeof(quic_frame);
    switch(frame.type){
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        usage +=  sizeof(quic_ack_range) * frame.ack.range_count;
        break;
    case QUIC_FRAME_CRYPTO:
        usage += frame.crypto.length;
        break;
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        usage += frame.close.reason_len;
        break;
    case QUIC_FRAME_NEW_CONNECTION_ID:
        usage += frame.new_id.length;
        break;
    case QUIC_FRAME_NEW_TOKEN:
        usage += frame.new_token.length;
        break;
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        usage += frame.datagram.length;
        break;
    default:
        if((frame.type >= QUIC_FRAME_STREAM_START_ID)
           &&(frame.type <= QUIC_FRAME_STREAM_END_ID))
        {
            usage += frame.stream.length;
        }
        break;
    }
    return usage;
}

quic_frame::quic_frame() {
    //全零即type=QUIC_FRAME_PADDING(0)，不持有任何指针
    type = 0;
    //规避-Wclass-memaccess,依赖type为首个成员且其后无填充
    memset(&extra, 0, sizeof(*this) - sizeof(type));
}

quic_frame::quic_frame(uint64_t t) {
    type = t;
    memset(&extra, 0, sizeof(*this) - sizeof(type));
}

quic_frame::quic_frame(quic_frame&& o) noexcept {
    type = o.type;
    memcpy(&extra, &o.extra, sizeof(*this) - sizeof(type));
    o.type = 0;
    memset(&o.extra, 0, sizeof(o) - sizeof(o.type));
}

quic_frame& quic_frame::operator=(quic_frame&& o) noexcept {
    if(this != &o){
        release();
        type = o.type;
        memcpy(&extra, &o.extra, sizeof(*this) - sizeof(type));
        o.type = 0;
        memset(&o.extra, 0, sizeof(o) - sizeof(o.type));
    }
    return *this;
}

quic_frame::~quic_frame(){
    release();
}

void quic_frame::release() noexcept {
    switch(type) {
    case QUIC_FRAME_ACK:
    case QUIC_FRAME_ACK_ECN:
        delete []ack.ranges;
        break;
    case QUIC_FRAME_CRYPTO:
        delete crypto.buffer;
        break;
    case QUIC_FRAME_CONNECTION_CLOSE:
    case QUIC_FRAME_CONNECTION_CLOSE_APP:
        delete []close.reason;
        break;
    case QUIC_FRAME_NEW_CONNECTION_ID:
        delete []new_id.id;
        break;
    case QUIC_FRAME_NEW_TOKEN:
        delete []new_token.token;
        break;
    case QUIC_FRAME_DATAGRAM:
    case QUIC_FRAME_DATAGRAM_LEN:
        delete datagram.buffer;
        break;
    default:
        if((type >= QUIC_FRAME_STREAM_START_ID) && (type <= QUIC_FRAME_STREAM_END_ID))
        {
            delete stream.buffer;
        }
        break;
    }
    type = 0;
    memset(&extra, 0, sizeof(*this) - sizeof(type));
}

std::string dumpHex(const void* data, size_t len){
    if(len == 0){
        return "";
    }
    std::string s = "0x";
    for(size_t i = 0; i < len; i++) {
        const char hex_digits[] = "0123456789abcdef";
        s += hex_digits[((uint8_t*)data)[i] >> 4];
        s += hex_digits[((uint8_t*)data)[i] & 0x0F];
    }
    return s;
}

static std::string reset_secret;

void generate_reset_secret(){
    EVP_PKEY* key = get_default_key();
    if(key == nullptr) {
        return;
    }
    static const char nonce[] = "sproxy-stateless-reset";
    char* token = nullptr;
    unsigned int sign_len;
    if(sign_data(key, nonce, sizeof(nonce), &token, &sign_len)){
        LOGE("QUIC failed to sign reset secret\n");
        return;
    }
    reset_secret = std::string(token, sign_len);
    free(token);
}

std::string sign_cid(const std::string& id) {
    std::string token;
    token.resize(EVP_MAX_MD_SIZE);
    unsigned int token_len;
    if(!HMAC(EVP_sha256(),
             reset_secret.c_str(),
             reset_secret.length(),
             (const uint8_t*)id.c_str(),
             id.length(),
             (uint8_t*)token.data(),
             &token_len))
    {
        return "";
    }
    assert(token_len >= QUIC_TOKEN_LEN);
    token.resize(QUIC_TOKEN_LEN);
    return token;
}


static int retry_aead_encrypt_decrypt(const char* key, const char* nonce,
                                     const cursor& aad,
                                     const cursor& input,
                                     cursor& output, bool encrypt) {
#ifdef USE_BORINGSSL
    const EVP_AEAD* aead = EVP_aead_aes_128_gcm();
    if (encrypt) {
        return aead_encrypt(aead, input, aad,
                           (const unsigned char*)key,
                           (const unsigned char*)nonce,
                           output);
    }
    return aead_decrypt(aead, input, aad,
                       (unsigned char*)key,
                       (unsigned char*)nonce,
                       output);
#else
    const EVP_CIPHER* cipher = EVP_aes_128_gcm();
    if (encrypt) {
        return aead_encrypt(cipher, input, aad,
                           (const unsigned char*)key,
                           (const unsigned char*)nonce,
                           output);
    }
    return aead_decrypt(cipher, input, aad,
                       (unsigned char*)key,
                       (unsigned char*)nonce,
                       output);
#endif
}

bool verify_retry_integrity_tag(const void* retry_packet, size_t packet_len,
                               const std::string& original_dcid, uint32_t version) {
    if (packet_len < 16) {
        // Packet too short to contain integrity tag
        return false;
    }

    const char* key = (version == QUIC_VERSION_2) ? retry_integrity_key_v2 : retry_integrity_key_v1;
    const char* nonce = (version == QUIC_VERSION_2) ? retry_integrity_nonce_v2 : retry_integrity_nonce_v1;

    // Prepare AAD: original_dcid_len + original_dcid + retry_packet_without_tag
    size_t aad_len = 1 + original_dcid.length() + packet_len - 16;
    char* aad = new char[aad_len];
    aad[0] = (char)original_dcid.length();
    memcpy(aad + 1, original_dcid.data(), original_dcid.length());
    memcpy(aad + 1 + original_dcid.length(), retry_packet, packet_len - 16);

    // Extract the tag from the packet
    const char* tag = (const char*)retry_packet + packet_len - 16;

    // Try to decrypt the tag (which should be all zeros)
    char plaintext[16];
    cursor aad_c(aad, aad_len);
    cursor tag_c(tag, 16);
    cursor plain_c(plaintext, sizeof(plaintext));
    int result = retry_aead_encrypt_decrypt(key, nonce, aad_c, tag_c, plain_c, false);

    delete[] aad;

    return result == 0;
}

size_t add_retry_integrity_tag(void* retry_packet, size_t packet_len,
                              const std::string& original_dcid, uint32_t version) {
    const char* key = (version == QUIC_VERSION_2) ? retry_integrity_key_v2 : retry_integrity_key_v1;
    const char* nonce = (version == QUIC_VERSION_2) ? retry_integrity_nonce_v2 : retry_integrity_nonce_v1;

    // Prepare AAD: original_dcid_len + original_dcid + retry_packet
    size_t aad_len = 1 + original_dcid.length() + packet_len;
    char* aad = new char[aad_len];
    aad[0] = (char)original_dcid.length();
    memcpy(aad + 1, original_dcid.data(), original_dcid.length());
    memcpy(aad + 1 + original_dcid.length(), retry_packet, packet_len);

    // The integrity tag is the 16-byte GCM tag produced by AEAD-sealing an
    // empty plaintext with the Retry Pseudo-Packet as AAD (RFC 9000 §17.2.5.3).
    char tag[16];
    char empty = 0;
    cursor aad_c(aad, aad_len);
    cursor empty_c(&empty, 0);
    cursor tag_c(tag, sizeof(tag));
    int tag_len = retry_aead_encrypt_decrypt(key, nonce, aad_c, empty_c, tag_c, true);

    delete[] aad;

    if (tag_len != 16) {
        return packet_len; // Failed to add tag
    }

    memcpy((char*)retry_packet + packet_len, tag, 16);
    return packet_len + 16;
}
