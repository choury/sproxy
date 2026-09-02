/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * This is a minimal TLS implementation intended only to parse the server name
 * extension.  This was created based primarily on Wireshark dissection of a
 * TLS handshake and RFC4366.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* strncpy() */
#include <errno.h>
#include "common/common.h"
#include "tls.h"
#include "misc/config.h"
#include "misc/cert_manager.h"

#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#ifdef HAVE_ECH
#include <openssl/rand.h>
#include <openssl/hpke.h>
#include "misc/util.h"
#include <fcntl.h>
#include <unistd.h>
#endif

const char *DEFAULT_CIPHER_LIST =
            "TLS13-AES-256-GCM-SHA384:"
            "TLS13-CHACHA20-POLY1305-SHA256:"
            "TLS13-AES-128-GCM-SHA256:"
            "TLS13-AES-128-CCM-8-SHA256:"
            "TLS13-AES-128-CCM-SHA256:"
            "ECDHE-RSA-AES128-GCM-SHA256:"
            "ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:"
            "ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:"
            "DHE-RSA-AES128-GCM-SHA256:"
            "DHE-DSS-AES128-GCM-SHA256:"
            "ECDHE+AES128:"
            "RSA+AES128:"
            "ECDHE+AES256:"
            "RSA+AES256:"
            "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";

#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

static int parse_extensions(const unsigned char*, size_t, char **);
static int parse_server_name_extension(const unsigned char *, size_t, char **);


/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
int parse_tls_header(const unsigned char *data, size_t data_len, char **hostname) {
    if (hostname == NULL)
        return -3;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return -1;

    /* SSL 2.0 compatible Client Hello
     *
     * High bit of first byte (length) and content type is Client Hello
     *
     * See RFC5246 Appendix E.2
     */
    if (data[0] & 0x80 && data[2] == 1) {
        LOGE("Received SSL 2.0 Client Hello which can not support SNI.\n");
        return -2;
    }

    char tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        LOGE("Request did not begin with TLS handshake: %d.\n", tls_content_type);
        LOG("%02x %02x %02x %02x %02x %02x %02x %02x\n",
	         data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7]);
        return -5;
    }

    char tls_version_major = data[1];
    char tls_version_minor = data[2];
    if (tls_version_major < 3) {
        LOGE("Received SSL %d.%d handshake which which can not support SNI.\n",
              tls_version_major, tls_version_minor);
        return -2;
    }

    /* TLS record length */
    size_t len = (data[3] << 8) + data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    if (TLS_HEADER_LEN + 1 > data_len) {
        return -5;
    }
    return parse_client_hello(data + TLS_HEADER_LEN, data_len - TLS_HEADER_LEN, hostname);
}

int parse_client_hello(const unsigned char*data, size_t data_len, char** hostname) {
    size_t pos = 0;
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        LOGE("Not a client hello\n");
        return -5;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len) {
        LOGE("Pos exceed\n");
        return -5;
    }
    size_t len = data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len) {
        LOGE("Pos exceed\n");
        return -5;
    }
    len = (data[pos] << 8) + data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len) {
        LOGE("Pos exceed\n");
        return -5;
    }
    len = data[pos];
    pos += 1 + len;

    if (pos == data_len /*&& tls_version_major == 3 && tls_version_minor == 0*/) {
        LOGE("Received SSL 3.0 handshake without extensions\n");
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len) {
        LOGE("Pos exceed\n");
        return -5;
    }
    len = (data[pos] << 8) + data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -1;
    return parse_extensions(data + pos, len, hostname);
}

static int
parse_extensions(const unsigned char *data, size_t data_len, char **hostname) {
    size_t pos = 0;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        size_t len = (data[pos + 2] << 8) + data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len) {
                LOGE("Pos exceed\n");
                return -5;
            }
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len) {
        LOGE("Unexpected Pos\n");
        return -5;
    }
    return -2;
}

static int
parse_server_name_extension(const unsigned char *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */

    while (pos + 3 < data_len) {
        size_t len = (data[pos + 1] << 8) + data[pos + 2];

        if (pos + 3 + len > data_len) {
            LOGE("Pos exceed\n");
            return -5;
        }

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL) {
                    LOGE("malloc() failure: %s\n", strerror(errno));
                    return -4;
                }

                strncpy(*hostname, (char*)data + pos + 3, len);

                (*hostname)[len] = '\0';

                return len;
            default:
                LOGE("Unknown server name extension name type: %d\n",
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len) {
        LOGE("Unexpected Pos\n");
        return -5;
    }

    return -2;
}

int verify_host_callback(int ok, X509_STORE_CTX *ctx){
    char    buf[256];
    X509   *err_cert;
    int     err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    /*
     * Catch a too long certificate chain. The depth limit set using
     * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
     * that whenever the "depth>verify_depth" condition is met, we
     * have violated the limit and want to log this error condition.
     * We must do it here, because the CHAIN_TOO_LONG error would not
     * be found explicitly; only errors introduced by cutting off the
     * additional certificates would be logged.
     */
    if (!ok) {
        LOGE("verify cert error:num=%d:%s:depth=%d:%s\n", err,
             X509_verify_cert_error_string(err), depth, buf);
    } else {
        LOGD(DSSL, "cert depth=%d:%s\n", depth, buf);
    }

    /*
     * At this point, err contains the last verification error. We can use
     * it for something special
     */
    if (!ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT || err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)) {
        X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
        LOGE("unable to verify issuer= %s\n", buf);
    }

    return opt.ignore_cert_error ? 1 : ok;
}

static int ssl_err_cb(const char* str, size_t len, void* arg){
    SSL* ssl = (SSL*)arg;
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    LOGE("SSL error sni:<%s> : %.*s", sni ? sni : "none", (int)len, str);
    return (int)len;
}

int ssl_get_error(SSL* ssl, int ret){
    if(ret <= 0){
        int error = SSL_get_error(ssl, ret);
        switch (error) {
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            errno = EAGAIN;
            break;
        case SSL_ERROR_ZERO_RETURN:
            ret = 0;
            errno = 0;
            break;
        case SSL_ERROR_SYSCALL:
            if(errno == 0){
                errno = EPIPE;
            }
            break;
        case SSL_ERROR_SSL:
            ERR_print_errors_cb(ssl_err_cb, ssl);
            /* FALLTHROUGH */
        default:
            errno = EIO;
            break;
        }
        if(ret == 0){
            ret = -errno;
        }
        ERR_clear_error();
    } else {
        errno = 0;
    }
    return ret;
}


void keylog_write_line(const SSL *ssl, const char *line){
    static const SSL* lssl = NULL;
    const char* filename = getenv("SSLKEYLOGFILE");
    if(filename == NULL){
        return;
    }
    FILE* f = fopen(filename, lssl==ssl ? "a" : "w");
    if(f == NULL){
        return;
    }
    fprintf(f, "%s\n", line);
    fclose(f);
    lssl = ssl;
}

#ifdef HAVE_QUIC

int sign_data(EVP_PKEY* key, const void* buff, int buff_len, char** sig, unsigned int* sig_len){
    *sig_len = EVP_PKEY_size(key);
    *sig = malloc(*sig_len);
    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if(EVP_SignInit(ctx, EVP_sha256()) != 1){
        LOGE("EVP_SignInit failed\n");
        goto error;
    }
    if(EVP_SignUpdate(ctx, buff, buff_len) != 1){
        LOGE("EVP_SignUpdate failed\n");
        goto error;
    }
    if(EVP_SignFinal(ctx, (unsigned char*)*sig, sig_len, key) != 1){
        LOGE("EVP_SignFinal failed\n");
        goto error;
    }

    EVP_MD_CTX_free(ctx);
    return 0;
error:
    EVP_MD_CTX_free(ctx);
    free(*sig);
    *sig = NULL;
    return -1;
}

int verify_data(const char* pub_key_file, const void* buff, size_t buff_len, const void* sig, size_t sig_len){
    FILE * f = fopen(pub_key_file, "r");
    EVP_PKEY *ec_key = PEM_read_PUBKEY(f,NULL,NULL,NULL);
    fclose(f);

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    if(EVP_VerifyInit(ctx, EVP_sha256()) != 1){
        LOGE("EVP_VerifyInit failed");
        goto error;
    }
    if(EVP_VerifyUpdate(ctx, buff, buff_len) != 1){
        LOGE("EVP_VerifyUpdate failed");
        goto error;
    }
    if(EVP_VerifyFinal(ctx, (unsigned char*)sig, sig_len, ec_key) != 1){
        LOGE("EVP_VerifyFinal failed");
        goto error;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(ec_key);
    return 0;
error:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(ec_key);
    return -1;
}

#endif


static const char* h3_alpn[] = {"h3", "r3", NULL};
static const char* h2_alpn[] = {"h2", "http/1.1", "r2", NULL};
static const char* h1_alpn[] = {"http/1.1", NULL};

static int select_alpn_cb(SSL *ssl,
                          const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    const char **priorities = (const char **)arg;
    for (size_t i = 0; priorities[i] != NULL; i++) {
        const unsigned char *p = in;
        while ((size_t)(p-in) < inlen) {
            uint8_t len = *p++;
            LOGD(DSSL, "check alpn: %.*s\n", len, p);
            if (len == strlen(priorities[i]) && strncmp((const char *) p, priorities[i], len) == 0) {
                LOGD(DSSL, "alpn pick %s\n", priorities[i]);
                *out = (unsigned char *) priorities[i];
                *outlen = strlen((char *) *out);
                return SSL_TLSEXT_ERR_OK;
            }
            p += len;
        }
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#ifndef USE_BORINGSSL
static int ssl_callback_ClientHello(SSL *ssl, int* al, void* arg){
    // ssl_callback_ServerName 已经把所有创建证书的活都干了, 这里保留一个空实现
    (void)ssl;
    (void)al;
    (void)arg;
    return SSL_CLIENT_HELLO_SUCCESS;
}
#endif

static int ssl_callback_ServerName(SSL *ssl, int* al, void* arg){
    (void)al;
    if(SSL_get_certificate(ssl)){
        return SSL_TLSEXT_ERR_OK;
    }
    const char* host = (const char*)arg;
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if(servername == NULL) {
        LOGD(DSSL, "no servername found for sni: %s\n", host);
    }else {
        LOGD(DSSL, "servername sni ext found for %s: %s\n", host, servername);
        host = servername;
    }

    // Check preloaded or generated cert
    const struct cert_pair* cert = generate_cert(host);
    if(cert) {
        X509* leaf = cert_pair_leaf(cert);
        SSL_use_certificate(ssl, leaf);
        SSL_use_PrivateKey(ssl, cert->key);
        // Install intermediate certs
        STACK_OF(X509)* chain = cert->chain;
        if(chain && sk_X509_num(chain) > 1) {
            int chain_total = sk_X509_num(chain);
            for(int i = 1; i < chain_total; ++i) {
                SSL_add1_chain_cert(ssl, sk_X509_value(chain, i));
            }
        }
        LOGD(DSSL, "generated cert for %s when ServerName\n", host);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("generate cert for sni: %s failed\n", host);
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}


#ifdef HAVE_ECH
/*
 * ECH密钥状态文件，每行一项:
 *   public_name=<域名>       ECHConfig里的公网回退名
 *   ech_config=<base64>      序列化的单个ECHConfig
 *   private_key=<base64>     X25519私钥(32字节)
 * 文件不存在且设置了ech-name时自动生成新密钥并落盘。
 */
static SSL_ECH_KEYS* server_ech_keys = NULL;

static int write_ech_key_file(const char* path, const char* public_name,
                              const uint8_t* ech_config, size_t ech_config_len,
                              const uint8_t* private_key, size_t private_key_len) {
    char config_b64[1024];
    char key_b64[64];
    //base64输出长度为4*ceil(len/3)，加结尾nul后必须先验长度再编码
    if((ech_config_len + 2) / 3 * 4 + 1 > sizeof(config_b64) ||
       (private_key_len + 2) / 3 * 4 + 1 > sizeof(key_b64)) {
        LOGE("ech key too long: %zd/%zd\n", ech_config_len, private_key_len);
        return -1;
    }
    Base64Encode((const char*)ech_config, ech_config_len, config_b64);
    Base64Encode((const char*)private_key, private_key_len, key_b64);
    //私钥文件必须0600且不跟随已存在的符号链接，生成路径保证文件不存在
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if(fd < 0) {
        LOGE("create %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    FILE* fp = fdopen(fd, "w");
    if(fp == NULL) {
        close(fd);
        return -1;
    }
    int ret = 0;
    if(fprintf(fp, "public_name=%s\n", public_name) < 0 ||
       fprintf(fp, "ech_config=%s\n", config_b64) < 0 ||
       fprintf(fp, "private_key=%s\n", key_b64) < 0 ||
       fclose(fp) != 0) {
        ret = -1;
    }
    return ret;
}

static SSL_ECH_KEYS* load_ech_keys() {
    if(server_ech_keys != NULL) {
        return server_ech_keys;
    }
    if(opt.ech_key == NULL) {
        return NULL;
    }
    EVP_HPKE_KEY* hpke_key = EVP_HPKE_KEY_new();
    SSL_ECH_KEYS* keys = SSL_ECH_KEYS_new();
    if(hpke_key == NULL || keys == NULL) {
        LOGE("alloc for ech keys failed\n");
        EVP_HPKE_KEY_free(hpke_key);
        SSL_ECH_KEYS_free(keys);
        return NULL;
    }
    uint8_t ech_config[512];
    size_t ech_config_len = 0;
    uint8_t private_key[EVP_HPKE_MAX_PRIVATE_KEY_LENGTH];
    size_t private_key_len = 0;
    char public_name[DOMAINLIMIT] = {0};
    FILE* fp = fopen(opt.ech_key, "r");
    if(fp == NULL && errno != ENOENT) {
        //权限/IO错误等必须如实报错，误生成新密钥会使已发布的DNS记录失效
        LOGE("open ech key file %s failed: %s\n", opt.ech_key, strerror(errno));
        goto err;
    }

    if(fp != NULL) {
        char line[2048];
        uint8_t bin[2048]; //与行缓冲对齐：2047个base64字符最多解码1535字节
        while(fgets(line, sizeof(line), fp)) {
            char b64[2048];
            size_t len;
            if(sscanf(line, "public_name=%255s", public_name) == 1) {
                continue;
            }
            if(sscanf(line, "ech_config=%2047s", b64) == 1) {
                len = Base64Decode(b64, strlen(b64), (char*)bin);
                if(len == 0 || len > sizeof(ech_config)) {
                    LOGE("invalid ech_config in %s\n", opt.ech_key);
                    goto err;
                }
                memcpy(ech_config, bin, len);
                ech_config_len = len;
                continue;
            }
            if(sscanf(line, "private_key=%2047s", b64) == 1) {
                len = Base64Decode(b64, strlen(b64), (char*)bin);
                if(len == 0 || len > sizeof(private_key)) {
                    LOGE("invalid private_key in %s\n", opt.ech_key);
                    goto err;
                }
                memcpy(private_key, bin, len);
                private_key_len = len;
                continue;
            }
        }
        fclose(fp);
        fp = NULL;
        if(EVP_HPKE_KEY_init(hpke_key, EVP_hpke_x25519_hkdf_sha256(),
                             private_key, private_key_len) != 1) {
            LOGE("ech private_key invalid: %s\n", opt.ech_key);
            goto err;
        }
    } else {
        //密钥文件不存在则生成新密钥
        if(opt.ech_name == NULL || opt.ech_name[0] == 0) {
            LOGE("ech-key %s not found and no ech-name set for generation\n", opt.ech_key);
            goto err;
        }
        uint8_t config_id = 0;
        RAND_bytes(&config_id, 1);
        uint8_t* marshaled = NULL;
        size_t marshaled_len = 0;
        if(EVP_HPKE_KEY_generate(hpke_key, EVP_hpke_x25519_hkdf_sha256()) != 1 ||
           SSL_marshal_ech_config(&marshaled, &marshaled_len, config_id, hpke_key,
                                  opt.ech_name, strlen(opt.ech_name)) != 1 ||
           marshaled_len > sizeof(ech_config)) {
            LOGE("generate ech key failed\n");
            OPENSSL_free(marshaled);
            goto err;
        }
        memcpy(ech_config, marshaled, marshaled_len);
        ech_config_len = marshaled_len;
        OPENSSL_free(marshaled);
        if(EVP_HPKE_KEY_private_key(hpke_key, private_key, &private_key_len,
                                    sizeof(private_key)) != 1) {
            goto err;
        }
        snprintf(public_name, sizeof(public_name), "%s", opt.ech_name);
        if(write_ech_key_file(opt.ech_key, public_name, ech_config, ech_config_len,
                              private_key, private_key_len) != 0) {
            //落盘失败视为致命：重启后会生成不同密钥，已发布的DNS ech值随之失效
            LOGE("persist ech key file %s failed\n", opt.ech_key);
            goto err;
        }
    }

    if(ech_config_len == 0 || private_key_len == 0) {
        LOGE("ech key file %s missing ech_config or private_key\n", opt.ech_key);
        goto err;
    }
    if(SSL_ECH_KEYS_add(keys, 1 /*is_retry_config*/, ech_config, ech_config_len, hpke_key) != 1) {
        LOGE("ech key/config mismatch in %s\n", opt.ech_key);
        goto err;
    }
    {
        //打印可发布到DNS HTTPS RR ech参数的值
        uint8_t* retry_configs = NULL;
        size_t retry_configs_len = 0;
        if(SSL_ECH_KEYS_marshal_retry_configs(keys, &retry_configs, &retry_configs_len) == 1) {
            char b64[2048];
            Base64Encode((const char*)retry_configs, retry_configs_len, b64);
            LOG("[ECH] server ech enabled, publish to DNS HTTPS RR: ech=%s\n", b64);
            OPENSSL_free(retry_configs);
        }
    }
    EVP_HPKE_KEY_free(hpke_key);
    server_ech_keys = keys;
    return keys;
err:
    if(fp) {
        fclose(fp);
    }
    EVP_HPKE_KEY_free(hpke_key);
    SSL_ECH_KEYS_free(keys);
    return NULL;
}
#endif

SSL_CTX* initssl(int quic, const char* host){
    const char** alpn_list = NULL;
    if(quic) {
        alpn_list = h3_alpn;
    }else if(!opt.disable_http2) {
        alpn_list = h2_alpn;
    }else {
        alpn_list = h1_alpn;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
#ifdef HAVE_QUIC
    if(quic){
        SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        SSL_CTX_set_ciphersuites(ctx, QUIC_CIPHERS);
        SSL_CTX_set1_groups_list(ctx, QUIC_GROUPS);
    }else {
#else
    (void)quic;
    {
#endif
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); // 去除支持SSLv2 SSLv3
        SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    /*
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    SSL_CTX_set_ecdh_auto(ctx, 1);
    */

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    LOGD(DSSL, "check cert for %s\n", host);
    const struct cert_pair* cert = lookup_cert(host);
    if (cert) {
        X509* leaf_cert = cert_pair_leaf(cert);
        if (SSL_CTX_use_certificate(ctx, leaf_cert) != 1) {
            ERR_print_errors_fp(stderr);
        }

        if (SSL_CTX_use_PrivateKey(ctx, cert->key) != 1) {
            ERR_print_errors_fp(stderr);
        }

        STACK_OF(X509)* chain = cert->chain;
        if (chain && sk_X509_num(chain) > 1) {
#ifndef USE_BORINGSSL
            SSL_CTX_clear_chain_certs(ctx);
#endif
            int chain_total = sk_X509_num(chain);
            for(int i = 1; i < chain_total; ++i) {
                X509* chain_cert = sk_X509_value(chain, i);
                if(chain_cert == NULL) {
                    continue;
                }
#ifdef USE_BORINGSSL
                if(SSL_CTX_add_extra_chain_cert(ctx, X509_dup(chain_cert)) != 1) {
                    ERR_print_errors_fp(stderr);
                }
#else
                if(SSL_CTX_add1_chain_cert(ctx, chain_cert) != 1) {
                    ERR_print_errors_fp(stderr);
                }
#endif
            }
        }

        if (SSL_CTX_check_private_key(ctx) != 1) {
            ERR_print_errors_fp(stderr);
        }
    }

    SSL_CTX_set_verify_depth(ctx, 10);
#ifndef USE_BORINGSSL
    // 设置 ClientHello 回调函数
    SSL_CTX_set_client_hello_cb(ctx, ssl_callback_ClientHello, (void*)host);
#endif
    SSL_CTX_set_tlsext_servername_callback(ctx, ssl_callback_ServerName);
    SSL_CTX_set_tlsext_servername_arg(ctx, (void*)host);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, alpn_list);
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_keylog_callback(ctx, keylog_write_line);
#ifdef HAVE_ECH
    //ECH协商成功后SNI回调/证书选择会透明反映inner ClientHello，无需额外处理
    SSL_ECH_KEYS* ech_keys = load_ech_keys();
    if(ech_keys != NULL && SSL_CTX_set1_ech_keys(ctx, ech_keys) != 1) {
        LOGE("SSL_CTX_set1_ech_keys failed\n");
        ERR_print_errors_fp(stderr);
    }
#endif
    return ctx;
}
