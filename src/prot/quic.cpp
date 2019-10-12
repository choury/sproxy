#include "quic.h"
#include <string.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* 0xef4fb0abb47470c41befcf8031334fae485e09a0 */
static const char* initial_salt = "\xef\x4f\xb0\xab\xb4\x74\x70\xc4\x1b\xef\xcf\x80\x31\x33\x4f\xae\x48\x5e\x09\xa0";
static const int initial_saltlen = 20;

class QuicClient{
public:
    virtual int SendPacket(const void* data, size_t len) = 0;
    void SendInit();
};


static int HKDF_Extract(const char* cid, size_t clen, char* prk){
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

struct HkdfLabel{
    uint16_t length;
    uint8_t  infoLen;
    char content[0];
} __attribute__((packed));

static int HKDF_Expand_Label(const char* prk, const char* info, const char *msg, char* okm, size_t len){
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
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;
    /* Initialise the encryption operation. */
    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
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
    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto err;
    ciphertext_len += len;
    /* Get the tag */
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto err;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


void QuicClient::SendInit() {
    char* id = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
}
