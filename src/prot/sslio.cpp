#include "sslio.h"
#include "tls.h"
#include "misc/net.h"
#include "misc/config.h"

#include <openssl/err.h>
#include <assert.h>
#include <errno.h>
#include <string.h>

const char *DEFAULT_CIPHER_LIST =
#if OPENSSL_VERSION_NUMBER > 0x10101000L
            "TLS13-AES-256-GCM-SHA384:"
            "TLS13-CHACHA20-POLY1305-SHA256:"
            "TLS13-AES-128-GCM-SHA256:"
            "TLS13-AES-128-CCM-8-SHA256:"
            "TLS13-AES-128-CCM-SHA256:"
#endif
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


SslRWer::SslRWer(int fd, const sockaddr_storage* peer,
                 SSL_CTX* ctx,
                 std::function<void(int ret, int code)> errorCB,
                 std::function<void(const sockaddr_storage&)> connectCB):
        StreamRWer(fd, peer, std::move(errorCB))
{
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    this->connectCB = std::move(connectCB);
    setEvents(RW_EVENT::READWRITE);
    stats = RWerStats::SslAccepting;
    handleEvent = (void (Ep::*)(RW_EVENT))&SslRWer::shakehandHE;
}

SslRWer::SslRWer(const char* hostname, uint16_t port, Protocol protocol,
                 std::function<void(int ret, int code)> errorCB,
                 std::function<void(const sockaddr_storage&)> connectCB):
        StreamRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB))
{
    assert(protocol == Protocol::TCP);
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == nullptr) {
        LOGE("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }
#if __ANDROID__
    if (SSL_CTX_load_verify_locations(ctx, opt.cafile, "/etc/security/cacerts/") != 1)
#else
    if (SSL_CTX_load_verify_locations(ctx, opt.cafile, "/etc/ssl/certs/") != 1)
#endif
        LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    ssl = SSL_new(ctx);
    if(ssl == nullptr){
        LOGE("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }
    SSL_set_options(ssl, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
    SSL_set_read_ahead(ssl, 1);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);
}

SslRWer::~SslRWer(){
    if(!SSL_in_init(ssl)){
        SSL_shutdown(ssl);
    }
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
}

void SslRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        checkSocket(__PRETTY_FUNCTION__);
        return connect();
    }
    if (!!(events & RW_EVENT::WRITE)) {
        setEvents(RW_EVENT::READWRITE);
        stats = RWerStats::SslConnecting;
        //ssl = SSL_new(ctx);
        SSL_set_fd(ssl, getFd());

        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname));

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);

        handleEvent = (void (Ep::*)(RW_EVENT))&SslRWer::shakehandHE;
        con_failed_job = updatejob(con_failed_job, std::bind(&SslRWer::connect, this), 1000);
    }
}

void SslRWer::shakehandHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR)) {
        ErrorHE(SSL_SHAKEHAND_ERR, checkSocket(__PRETTY_FUNCTION__));
        return;
    }
    if (!!(events & RW_EVENT::READ) || !!(events & RW_EVENT::WRITE)) {
        if((ctx?sconnect():saccept()) == 1) {
            Connected(addrs.front());
            //in case some data in ssl buffer
            flags |= RWER_READING;
            ReadData();
            flags &= ~RWER_READING;
        }else if(errno ==  EAGAIN){
            setEvents(RW_EVENT::READWRITE);
        }else{
            int error = errno;
            LOGE("(%s): ssl %s error:%s\n", hostname, ctx?"connect":"accept", strerror(error));
            ErrorHE(SSL_SHAKEHAND_ERR, error);
        }
    }
}

int SslRWer::saccept(){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_accept(ssl));
}

int SslRWer::sconnect(){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_connect(ssl));
}

ssize_t SslRWer::Read(void* buff, size_t len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_read(ssl, buff, len));
}

ssize_t SslRWer::Write(const void* buff, size_t len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_write(ssl, buff, len));
}

void SslRWer::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int SslRWer::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

void SslRWer::set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg){
//    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb);
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_CTX_set_tlsext_servername_callback(ctx, cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}
