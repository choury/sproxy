#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "req/guest3.h"
#endif
#include "req/cli.h"
#include "misc/job.h"
#include "misc/config.h"

#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//do nothing, useful for vpn only
int protectFd(int){
    return 1;
}

static int select_alpn_cb(SSL *ssl,
                          const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    std::set<std::string> proset;
    const unsigned char *p = in;
    while ((size_t)(p-in) < inlen) {
        uint8_t len = *p++;
        proset.insert(std::string((const char *)p, len));
        p += len;
    }
    if (opt.quic_mode && proset.count("h3")){
        *out = (unsigned  char*)"h3";
        *outlen = strlen((char *)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    if (!opt.disable_http2 && proset.count("h2")) {
        *out = (unsigned char *)"h2";
        *outlen = strlen((char *)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    if (proset.count("http/1.1")) {
        *out = (unsigned char *)"http/1.1";
        *outlen = strlen((char *)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int ssl_callback_ServerName(SSL *ssl, int*, void*){
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        //TODO: new sni mode
    }
    return 0;
}

static SSL_CTX* initssl(int quic, const char *ca, const char *cert, const char *key){
    assert(cert && key);

    SSL_CTX *ctx = nullptr;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ctx = SSL_CTX_new(SSLv23_server_method());
#else
    ctx = SSL_CTX_new(TLS_server_method());
#endif
    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        return nullptr;
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
    */
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (ca && SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    //加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_set_tlsext_servername_callback(ctx, ssl_callback_ServerName);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, nullptr);
    SSL_CTX_set_read_ahead(ctx, 1);
    return ctx;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    if(opt.cert && opt.key){
        SSL_CTX * ctx = initssl(opt.quic_mode, opt.cafile, opt.cert, opt.key);
        opt.CPORT = opt.CPORT ?: 443;
#ifdef HAVE_QUIC
        if(opt.quic_mode){
            int svsk_quic = ListenNet(SOCK_DGRAM, opt.CPORT);
            if(svsk_quic <  0) {
                return -1;
            }
            new Quic_server(svsk_quic, ctx);
        }else {
#else
        assert(opt.quic_mode == 0);
        {
#endif
            int svsk_https = ListenNet(SOCK_STREAM, opt.CPORT);
            if (svsk_https < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_https, ctx);
        }
    }else{
        if(opt.sni_mode) {
            opt.CPORT = opt.CPORT ?: 443;
            int svsk_sni = ListenNet(SOCK_STREAM, opt.CPORT);
            if (svsk_sni < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(svsk_sni, nullptr);
        }else{
            opt.CPORT = opt.CPORT ?: 80;
            int svsk_http = ListenNet(SOCK_STREAM, opt.CPORT);
            if (svsk_http < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_http, nullptr);
        }
    }
    if(opt.admin && strlen(opt.admin) > 0){
        int svsk_cli = -1;
        if(strncmp(opt.admin, "tcp:", 4) == 0){
            svsk_cli = ListenNet(SOCK_STREAM, atoi(opt.admin+4));
        }else{
            svsk_cli = ListenUnix(opt.admin);
        }
        if(svsk_cli < 0){
            return -1;
        }
        new Cli_server(svsk_cli);
    }
    LOG("Accepting connections ...\n");
    while (true) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            return 6;
        }
    }
}
