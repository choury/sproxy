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
#ifndef TLS_H__
#define TLS_H__
#include <openssl/ssl.h>

#ifdef  __cplusplus
extern "C" {
#endif


#ifdef USE_BORINGSSL
#define QUIC_CIPHERS                                              \
   TLS1_3_RFC_AES_256_GCM_SHA384                                  \
   ":" TLS1_3_RFC_AES_128_GCM_SHA256                              \
   ":" TLS1_3_RFC_CHACHA20_POLY1305_SHA256                        \
   ":" TLS1_TXT_ECDHE_RSA_WITH_AES_256_GCM_SHA384                 \
   ":" TLS1_TXT_ECDH_RSA_WITH_AES_256_GCM_SHA384                  \

#else
#define QUIC_CIPHERS                                              \
   TLS1_3_RFC_AES_256_GCM_SHA384                                  \
   ":" TLS1_3_RFC_AES_128_GCM_SHA256                              \
   ":" TLS1_3_RFC_CHACHA20_POLY1305_SHA256                        \

#endif


#define QUIC_GROUPS "P-256:X25519:P-384:P-521"

#ifdef USE_BORINGSSL
#define SSL_CTX_set_ciphersuites SSL_CTX_set_cipher_list
#endif

int parse_client_hello(const unsigned char*data, size_t data_len, char** hostname);
int parse_tls_header(const unsigned char *data, size_t data_len, char **hostname);
int verify_host_callback(int ok, X509_STORE_CTX *ctx);
int ssl_get_error(SSL* ssl, int ret);
void keylog_write_line(const SSL *ssl, const char *line);

int sign_data(EVP_PKEY* key, const void* buff, int buff_len, char** sig, unsigned int* sig_len);
int verify_data(const char* pub_key_file, const void* buff, size_t buff_len, const void* sig, size_t sig_len);
SSL_CTX* initssl(int quic, const char* host);
#ifdef  __cplusplus
}
#endif

#endif
