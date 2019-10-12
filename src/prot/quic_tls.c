#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* 0xef4fb0abb47470c41befcf8031334fae485e09a0 */
//static const char* initial_salt = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0";
static const char* initial_salt = "\xc3\xee\xf7\x12\xc7\x2e\xbb\x5a\x11\xa7\xd2\x43\x2b\xb4\x63\x65\xbe\xf9\xf5\x02";
static const int initial_saltlen = 20;

int variable_encode(uint64_t value, unsigned char* data){
    if(value <= 63){
        data[0] = (unsigned char)value;
        return 1;
    }
    if(value <= 16383){
        data[0] = 0x40 | (value >> 8);
        data[1] = value & 0xff;
        return 2;
    }
    if(value <= 1073741823){
        data[0] = 0x80 | (value >> 16);
        data[1] = (value >> 8) & 0xff;
        data[2] = value & 0xff;
        return 3;
    }
    if(value <= 4611686018427387903ull){
        data[0] = 0xc0 | (value >> 24);
        data[1] = (value >> 16) & 0xff;
        data[2] = (value >> 8) & 0xff;
        data[3] = value & 0xff;
        return 4;
    }
    return 0;
}

int variable_decode(unsigned char* data, uint64_t* value){
    size_t size = (data[0] & 0xc0) >> 6;
    switch(size){
    case 0:
        *value = data[0];
        return 1;
    case 1:
        *value = ((data[0]&0x3f) << 8ull) | data[1];
        return 2;
    case 2:
        *value = ((data[0]&0x3f) << 16ull) | (data[1] << 8) | data[2];
        return 3;
    case 3:
        *value = ((data[0]&0x3f) << 24ull) | (data[1] << 16) | (data[2] << 8) | data[3];
        return 4;
    }
    return 0;
}

int HKDF_Extract(const char* cid, size_t clen, char* prk){
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t hashlen = EVP_MD_size(EVP_sha256());
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
    return 0;
err:
    EVP_PKEY_CTX_free(pctx);
    return -1;
}

typedef struct HkdfLabel{
    uint16_t length;
    uint8_t  infoLen;
    char content[0];
} __attribute__((packed)) HkdfLabel;

int HKDF_Expand_Label(const char* prk, const char* info, const char *msg, char* okm, size_t len){
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

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t hashlen = EVP_MD_size(EVP_sha256());
    if (EVP_PKEY_derive_init(pctx) <= 0)
        goto err;
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0)
        goto err;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, prk, hashlen) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, labelLen) <= 0)
        goto err;
    if(EVP_PKEY_derive(pctx, (unsigned char*)okm, &len) <=0 )
        goto err;
    EVP_PKEY_CTX_free(pctx);
    return 0;
err:
    EVP_PKEY_CTX_free(pctx);
    return -1;
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    /* Create and initialise the context */
    if(ctx == NULL)
        return -1;
    /* Initialise the encryption operation. */
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
        goto err;
    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
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

    const int tag_len = 16;
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, ciphertext + ciphertext_len) != 1)
        goto err;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len + tag_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_encode(const unsigned char* key,
               const unsigned char* data, int data_len,
               unsigned char* out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, outlen;
    if(ctx == NULL)
        return -1;
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1)
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