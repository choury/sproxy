#include "sslio.h"
#include "tls.h"
#include "misc/net.h"
#include "misc/config.h"

#include <openssl/err.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#if __ANDROID__
extern std::string getExternalFilesDir();
#endif

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
    SSL_set_accept_state(ssl);

    BIO_set_mem_eof_return(in_bio, -1);
    BIO_set_mem_eof_return(out_bio, -1);
    SSL_set_bio(ssl, in_bio, out_bio);
}

SslRWer::SslRWer(const char* hostname, uint16_t port, Protocol protocol,
                 std::function<void(int ret, int code)> errorCB,
                 std::function<void(const sockaddr_storage&)> connectCB):
        StreamRWer(hostname, port, protocol, std::move(errorCB), std::move(connectCB))
{
    assert(protocol == Protocol::TCP);
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == nullptr) {
        LOGF("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_CTX_set_keylog_callback(ctx, keylog_write_line);
#if __ANDROID__
    if (SSL_CTX_load_verify_locations(ctx, (getExternalFilesDir() + CABUNDLE).c_str(), "/etc/security/cacerts/") != 1)
#else
    if (SSL_CTX_load_verify_locations(ctx, CABUNDLE, "/etc/ssl/certs/") != 1)
#endif
        LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    ssl = SSL_new(ctx);
    if(ssl == nullptr){
        LOGF("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
    }
    SSL_set_options(ssl, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
    SSL_set_read_ahead(ssl, 1);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, hostname);

    BIO_set_mem_eof_return(in_bio, -1);
    BIO_set_mem_eof_return(out_bio, -1);
    SSL_set_bio(ssl, in_bio, out_bio);
}

SslRWer::~SslRWer(){
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
}

void SslRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        int error = checkSocket(__PRETTY_FUNCTION__ );
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SslRWer::connectFailed, this, error), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        assert(!addrs.empty());
        setEvents(RW_EVENT::READWRITE);
        stats = RWerStats::SslConnecting;
        //ssl = SSL_new(ctx);
        //SSL_set_fd(ssl, getFd());

        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname));

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);

        handleEvent = (void (Ep::*)(RW_EVENT))&SslRWer::shakehandHE;
        con_failed_job = updatejob(con_failed_job,
                                   std::bind(&SslRWer::connectFailed, this, ETIMEDOUT), 2000);
    }
}

int SslRWer::fill_in_bio() {
    char buff[BUF_LEN];
    while(true) {
        ssize_t ret = read(getFd(), buff, sizeof(buff));
        if (ret > 0) {
            BIO_write(in_bio, buff, ret);
            continue;
        } else if (ret == 0) {
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            break;
        } else if (errno == EAGAIN) {
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return -1;
    }
    return 1;
}

int SslRWer::sink_out_bio(uint64_t id) {
    while(BIO_ctrl_pending(out_bio)) {
        char buff[BUF_LEN];
        int ret = BIO_read(out_bio, buff, sizeof(buff));
        if (ret > 0) {
            wbuff.push(wbuff.end(), Buffer{std::make_shared<Block>(buff, ret), (size_t)ret, id});
        }
    }
    return 1;
}

void SslRWer::shakehandHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR)) {
        return ErrorHE(SSL_SHAKEHAND_ERR, checkSocket(__PRETTY_FUNCTION__));
    }
    if(!!(events & RW_EVENT::READ)) {
        if(fill_in_bio() <= 0) return;
    }
    if(do_handshake() == 1){
    }else if(errno == EAGAIN){
        if(SSL_want_write(ssl)){
            setEvents(RW_EVENT::READWRITE);
        }else{
            setEvents(RW_EVENT::READ);
        }
    }else{
        int error = errno;
        LOGE("(%s): ssl %s error:%s\n", hostname, ctx?"connect":"accept", strerror(error));
        ErrorHE(SSL_SHAKEHAND_ERR, error);
        return;
    }

    sink_out_bio(0);
    if(SSL_is_init_finished(ssl)) {
        connected(addrs.front());
        //in case some data in ssl buffer
        ReadData();
    }
    SendData();
}

int SslRWer::do_handshake() {
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_do_handshake(ssl));
}

/*
ssize_t SslRWer::Read(void* buff, size_t len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_read(ssl, buff, len));
}
 */

void SslRWer::ReadData() {
    if(fill_in_bio() <= 0) return;
    while(true) {
        size_t left = rb.left();
        if (left == 0) {
            break;
        }
        ERR_clear_error();
        ssize_t ret = ssl_get_error(ssl, SSL_read(ssl, rb.end(), left));
        if (ret > 0) {
            rb.append((size_t) ret);
            ConsumeRData(0);
            continue;
        }else if(ret == 0) {
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            break;
        }else if(errno == EAGAIN) {
            break;
        }
        ErrorHE(SSL_SHAKEHAND_ERR, errno);
        return;
    }
    ConsumeRData(0);
}

void SslRWer::buffer_insert(Buffer &&bb) {
    if(stats == RWerStats::Error) {
        return;
    }
    addEvents(RW_EVENT::WRITE);
    if(bb.len == 0) {
        SSL_shutdown(ssl);
    }else {
        ERR_clear_error();
        while(bb.len > 0) {
            ssize_t ret = ssl_get_error(ssl, SSL_write(ssl, bb.data(), bb.len));
            if(ret > 0) {
                bb.reserve(ret);
                continue;
            }
            ErrorHE(SSL_SHAKEHAND_ERR, errno);
            return;
        }
    }
    sink_out_bio(bb.id);
}

/*
ssize_t SslRWer::Write(const void* buff, size_t len, uint64_t){
    if(len == 0){
        assert(flags & RWER_SHUTDOWN);
        SSL_shutdown(ssl);
        return 0;
    }
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_write(ssl, buff, len));
}
 */

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

void SslRWer::dump_status(Dumper dp, void *param) {
    dp(param, "SslRWer <%d> (%s): %s\nrlen: %zu, wlen: %zu, stats: %d, event: %s\n",
       getFd(), getPeer(), SSL_state_string_long(ssl),
       rlength(0), wbuff.length(), (int)getStats(), events_string[(int)getEvents()]);
}
