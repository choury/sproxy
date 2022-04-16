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
#include "tls.h"
#include "common/common.h"
#include "misc/config.h"

#include <openssl/err.h>

int parse_tls_header(const char *, size_t, char **);
static int parse_extensions(const char *, size_t, char **);
static int parse_server_name_extension(const char *, size_t, char **);



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
int parse_tls_header(const char *data, size_t data_len, char **hostname) {
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
    size_t len = ((unsigned char)data[3] << 8) +
        (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = Min(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return -1;

    /*
     * Handshake
     */
    size_t pos = TLS_HEADER_LEN;
    if (pos + 1 > data_len) {
        return -5;
    }
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
    if (pos + 1 > data_len)
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return -5;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        LOGE("Received SSL 3.0 handshake without extensions\n");
        return -2;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return -5;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return -5;
    return parse_extensions(data + pos, len, hostname);
}

static int
parse_extensions(const char *data, size_t data_len, char **hostname) {
    size_t pos = 0;

    /* Parse each 4 bytes for the extension header */
    while (pos + 4 <= data_len) {
        /* Extension Length */
        size_t len = ((unsigned char)data[pos + 2] << 8) +
            (unsigned char)data[pos + 3];

        /* Check if it's a server name extension */
        if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
            /* There can be only one extension of each type, so we break
               our state and move p to beinnging of the extension here */
            if (pos + 4 + len > data_len)
                return -5;
            return parse_server_name_extension(data + pos + 4, len, hostname);
        }
        pos += 4 + len; /* Advance to the next extension header */
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

    return -2;
}

static int
parse_server_name_extension(const char *data, size_t data_len,
        char **hostname) {
    size_t pos = 2; /* skip server name list length */

    while (pos + 3 < data_len) {
        size_t len = ((unsigned char)data[pos + 1] << 8) +
            (unsigned char)data[pos + 2];

        if (pos + 3 + len > data_len)
            return -5;

        switch (data[pos]) { /* name type */
            case 0x00: /* host_name */
                *hostname = malloc(len + 1);
                if (*hostname == NULL) {
                    LOGE("malloc() failure: %s\n", strerror(errno));
                    return -4;
                }

                strncpy(*hostname, data + pos + 3, len);

                (*hostname)[len] = '\0';

                return len;
            default:
                LOGE("Unknown server name extension name type: %d\n",
                      data[pos]);
        }
        pos += 3 + len;
    }
    /* Check we ended where we expected to */
    if (pos != data_len)
        return -5;

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
//        LOG("cert depth=%d:%s\n", depth, buf);
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

static int ssl_err_cb(const char* str, size_t len, void* _){
    (void)_;
    LOGE("SSL error: %.*s", (int)len, str);
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
            ERR_print_errors_cb(ssl_err_cb, NULL);
            /* FALLTHROUGH */
        default:
            errno = EIO;
            break;
        }
        if(ret == 0){
            ret = -errno;
        }
        ERR_clear_error();
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
