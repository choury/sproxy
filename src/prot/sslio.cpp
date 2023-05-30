#include "sslio.h"
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

template<class T>
SslRWerBase<T>::~SslRWerBase(){
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
}

void SslRWer<StreamRWer>::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        int error = this->checkSocket(__PRETTY_FUNCTION__ );
        this->con_failed_job = this->updatejob(this->con_failed_job,
                                   std::bind(&SslRWer::connectFailed, this, error), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        LOGD(DSSL, "[%s] connected from fd, start handshark\n", server.c_str());
        assert(!this->addrs.empty());
        this->setEvents(RW_EVENT::READWRITE);
        this->stats = RWerStats::Connected;
        this->sslStats = SslStats::SslConnecting;
        //ssl = SSL_new(ctx);
        //SSL_set_fd(ssl, getFd());

        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, this->hostname, strlen(this->hostname));

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);

        this->handleEvent = (void (Ep::*)(RW_EVENT))&SslRWer::shakehandHE;
        this->con_failed_job = this->updatejob(this->con_failed_job,
                                   std::bind(&SslRWer::connectFailed, this, ETIMEDOUT), 2000);
    }
}


template<class T>
int SslRWerBase<T>::sink_out_bio(uint64_t id) {
    while(BIO_ctrl_pending(out_bio)) {
        char buff[BUF_LEN];
        int ret = BIO_read(out_bio, buff, sizeof(buff));
        LOGD(DSSL, "[%s] send %d bytes to fd\n", server.c_str(), (int)ret);
        if (ret > 0) {
            this->wbuff.push(this->wbuff.end(), Buffer{std::make_shared<Block>(buff, ret), (size_t)ret, id});
        }
    }
    return 1;
}

template<class T>
void SslRWerBase<T>::shakehandHE(RW_EVENT events){
    if (!!(events & RW_EVENT::ERROR) || !!(events & RW_EVENT::READEOF)) {
        return this->ErrorHE(SSL_SHAKEHAND_ERR, this->checkSocket(__PRETTY_FUNCTION__));
    }
    if(sslStats != SslStats::SslAccepting && sslStats != SslStats::SslConnecting) {
        LOGE("[%s] wrong ssl stats: %d\n", server.c_str(), (int)this->sslStats);
        return this->ErrorHE(SSL_SHAKEHAND_ERR, EINVAL);
    }
    if(!!(events & RW_EVENT::READ)) {
        fill_in_bio();
    }
    if(do_handshake() == 1){
        sslStats = SslStats::Established;
        LOGD(DSSL, "[%s] ssl handshake success\n", server.c_str());
    }else if(errno == EAGAIN){
        if(this->stats != RWerStats::Connected) {
            LOGE("[%s]: ssl handshake EAGAIN with wrong stats: %d\n", server.c_str(), (int)this->stats);
            this->ErrorHE(SSL_SHAKEHAND_ERR, PEER_LOST_ERR);
            return;
        }
        if(SSL_want_write(ssl)){
            this->setEvents(RW_EVENT::READWRITE);
        }
    }else{
        int error = errno;
        sink_out_bio(0);
        LOGE("[%s]: ssl %s error:%s\n", server.c_str(), ctx?"connect":"accept", strerror(error));
        this->ErrorHE(SSL_SHAKEHAND_ERR, error);
        return;
    }

    sink_out_bio(0);
    if(sslStats == SslStats::Established) {
        call_connected();
        //in case some data in ssl buffer
        ReadData();
    }
    this->SendData();
}

template<class T>
int SslRWerBase<T>::do_handshake() {
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_do_handshake(ssl));
}

/*
ssize_t SslRWer::Read(void* buff, size_t len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_read(ssl, buff, len));
}
 */

template<class T>
void SslRWerBase<T>::ReadData() {
    fill_in_bio();
    while(true) {
        size_t left = this->rb.left();
        if (left == 0) {
            break;
        }
        ERR_clear_error();
        ssize_t ret = ssl_get_error(ssl, SSL_read(ssl, this->rb.end(), left));
        LOGD(DSSL, "[%s] SSL_read %d bytes\n", server.c_str(), (int)ret);
        if (ret > 0) {
            this->rb.append((size_t) ret);
            this->ConsumeRData(0);
            continue;
        }else if(ret == 0) {
            this->stats = RWerStats::ReadEOF;
            this->sslStats = SslStats::SslEOF;
            this->delEvents(RW_EVENT::READ);
            break;
        }else if(errno == EAGAIN && this->stats == RWerStats::Connected) {
            // we can't read any data more if stats is abnormal
            break;
        }
        this->ErrorHE(SSL_SHAKEHAND_ERR, errno);
        return;
    }
    this->ConsumeRData(0);
}

template<class T>
void SslRWerBase<T>::buffer_insert(Buffer &&bb) {
    if(this->stats == RWerStats::Error) {
        return;
    }
    this->addEvents(RW_EVENT::WRITE);
    if(bb.len == 0) {
        SSL_shutdown(ssl);
        this->flags |= RWER_SHUTDOWN;
    }else {
        ERR_clear_error();
        while(bb.len > 0) {
            ssize_t ret = ssl_get_error(ssl, SSL_write(ssl, bb.data(), bb.len));
            LOGD(DSSL, "[%s] SSL_write %d bytes\n", server.c_str(), (int)ret);
            if(ret > 0) {
                bb.reserve(ret);
                continue;
            }
            this->ErrorHE(SSL_SHAKEHAND_ERR, errno);
            return;
        }
    }
    sink_out_bio(bb.id);
}

template<class T>
bool SslRWerBase<T>::IsConnected() {
    return sslStats == SslStats::Established;
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

template<class T>
void SslRWerBase<T>::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

template<class T>
int SslRWerBase<T>::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

template<class T>
void SslRWerBase<T>::set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg){
//    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb);
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_CTX_set_tlsext_servername_callback(ctx, cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}

template<class T>
void SslRWerBase<T>::set_server_name(const std::string& arg) {
    server = arg;
    SSL_set_app_data(ssl, server.c_str());
}

template<class T>
void SslRWerBase<T>::dump_status(Dumper dp, void *param) {
    dp(param, "SslRWer <%d> (%s -> %s): %s\nrlen: %zu, wlen: %zu, stats: %d, sslStats: %d, event: %s\n",
       this->getFd(), this->getPeer(), server.c_str(), SSL_state_string_long(ssl),
       this->rlength(0), this->wbuff.length(),
       (int)this->getStats(), (int)this->sslStats,
       events_string[(int)this->getEvents()]);
}

SslRWer<StreamRWer>::SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
        SslRWerBase<StreamRWer>(hostname, port, protocol, std::move(errorCB))
    {
        assert(this->protocol == Protocol::TCP);
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
        SSL_set_tlsext_host_name(ssl, this->hostname);

        BIO_set_mem_eof_return(in_bio, -1);
        BIO_set_mem_eof_return(out_bio, -1);
        SSL_set_bio(ssl, in_bio, out_bio);
        set_server_name(hostname);
}

int SslRWer<StreamRWer>::fill_in_bio() {
    char buff[BUF_LEN];
    while(true) {
        ssize_t ret = read(this->getFd(), buff, sizeof(buff));
        LOGD(DSSL, "[%s] read %d bytes from fd\n", server.c_str(), (int)ret);
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
    return BIO_ctrl_pending(in_bio);
}


int SslRWer<MemRWer>::fill_in_bio() {
    if(stats == RWerStats::ReadEOF || sslStats == SslStats::SslEOF) {
        delEvents(RW_EVENT::READ);
    }
    return BIO_ctrl_pending(in_bio);
}

void SslRWer<MemRWer>::push(Buffer &&bb) {
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        BIO_write(in_bio, bb.data(), (int)bb.len);
    }
    addEvents(RW_EVENT::READ);
}

template class SslRWerBase<StreamRWer>;
template class SslRWerBase<MemRWer>;
