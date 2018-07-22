#include "misc/sslio.h"
#include "misc/job.h"
#include "misc/net.h"

#include <openssl/err.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

static int verify_host_callback(int ok, X509_STORE_CTX *ctx){
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
    if (!ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT))
    {
        X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
        LOGE("unable to get issuer= %s\n", buf);
    }

    if (ignore_cert_error)
        return 1;
    else
        return ok; 
}


SslRWer::SslRWer(int fd, SSL_CTX* ctx, std::function<void(int ret, int code)> errorCB):
        StreamRWer(fd, errorCB)
{
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    setEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Ep::*)(uint32_t))&SslRWer::shakehandHE;
}

SslRWer::SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
        StreamRWer(hostname, port, protocol, errorCB)
{
    if(protocol == Protocol::TCP){
        ctx = SSL_CTX_new(SSLv23_client_method());
    }else{
        ctx = SSL_CTX_new(DTLS_client_method());
    }

    if (ctx == NULL) {
        LOGE("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        throw 0;
    }

#ifdef __ANDROID__
    if (SSL_CTX_load_verify_locations(ctx, cafile, "/etc/security/cacerts/") != 1)
#else
    if (SSL_CTX_load_verify_locations(ctx, cafile, "/etc/ssl/certs/") != 1)
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
    SSL_set_tlsext_host_name(ssl, hostname);
}

static int ssl_err_cb(const char* str, size_t len, void* ){
    LOGE("SSL error: %*s\n", (int)len, str);
    return len;
}

int SslRWer::get_error(int ret){
    if(ret < 0){
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
                break;
            case SSL_ERROR_SSL:
                ERR_print_errors_cb(ssl_err_cb, nullptr);
                /* FALLTHRU */
            default:
                errno = EIO;
                break;
        }
        ERR_clear_error();
    }
    return ret;
}

int SslRWer::sconnect(){
    return get_error(SSL_connect(ssl));
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

void SslRWer::waitconnectHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        Checksocket(fd, __PRETTY_FUNCTION__);
        close(fd);
        fd = -1;
        return retryconnect(CONNECT_FAILED);
    }
    if (events & EPOLLOUT) {
        setEpoll(EPOLLIN | EPOLLOUT);
        if(protocol == Protocol::TCP){
            //ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
        }else{
            BIO* bio = BIO_new_dgram(fd, BIO_NOCLOSE);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addrs.front());

            SSL_set_bio(ssl, bio, bio);
        }

        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, hostname, 0);

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);

        handleEvent = (void (Ep::*)(uint32_t))&SslRWer::shakehandHE;
        add_delayjob(std::bind(&SslRWer::con_failed, this), this, 30000);
    }
}

void SslRWer::shakehandHE(uint32_t events){
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, Checksocket(fd, __PRETTY_FUNCTION__));
        return;
    }
    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = ctx?sconnect():saccept();
        if (ret != 1) {
            if (errno != EAGAIN) {
                int error = errno;
                LOGE("(%s): ssl connect error:%s\n", hostname, strerror(error));
                errorCB(SSL_SHAKEHAND_ERR, error);
            }
            return;
        }
        if(connectCB){
            connectCB();
        }
        handleEvent = (void (Ep::*)(uint32_t))&SslRWer::defaultHE;
        del_delayjob(std::bind(&SslRWer::con_failed, this), this);
    }
}

int SslRWer::saccept(){
    return get_error(SSL_accept(ssl));
}

ssize_t SslRWer::Read(void* buff, size_t len){
    return get_error(SSL_read(ssl, buff, len));
}

ssize_t SslRWer::Write(const void* buff, size_t len){
    return get_error(SSL_write(ssl, buff, len));
}

void SslRWer::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int SslRWer::set_alpn(const unsigned char *s, unsigned int len){
    return get_error(SSL_set_alpn_protos(ssl, s, len));
}

void SslRWer::set_hostname_callback(void (* cb)(void)){
    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb);
}

