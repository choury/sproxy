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
        LOGD(DSSL, "connected from fd, start handshark\n");
        assert(!this->addrs.empty());
        this->setEvents(RW_EVENT::READWRITE);
        this->stats = RWerStats::SslConnecting;
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
        LOGD(DSSL, "send %d bytes to fd\n", (int)ret);
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
    if(this->stats != RWerStats::SslAccepting && this->stats != RWerStats::SslConnecting) {
        return this->ErrorHE(SSL_SHAKEHAND_ERR, EINVAL);
    }
    if(!!(events & RW_EVENT::READ)) {
        if(fill_in_bio() <= 0) return;
    }
    if(do_handshake() == 1){
        LOGD(DSSL, "ssl handshake success\n");
    }else if(errno == EAGAIN){
        if(SSL_want_write(ssl)){
            this->setEvents(RW_EVENT::READWRITE);
        }else{
            this->setEvents(RW_EVENT::READ);
        }
    }else{
        int error = errno;
        LOGE("(%s): ssl %s error:%s\n", this->getPeer(), ctx?"connect":"accept", strerror(error));
        this->ErrorHE(SSL_SHAKEHAND_ERR, error);
        return;
    }

    sink_out_bio(0);
    if(SSL_is_init_finished(ssl)) {
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
    if(fill_in_bio() < 0) return;
    while(true) {
        size_t left = this->rb.left();
        if (left == 0) {
            break;
        }
        ERR_clear_error();
        ssize_t ret = ssl_get_error(ssl, SSL_read(ssl, this->rb.end(), left));
        LOGD(DSSL, "SSL_read %d bytes\n", (int)ret);
        if (ret > 0) {
            this->rb.append((size_t) ret);
            this->ConsumeRData(0);
            continue;
        }else if(ret == 0) {
            this->stats = RWerStats::ReadEOF;
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
    }else {
        ERR_clear_error();
        while(bb.len > 0) {
            ssize_t ret = ssl_get_error(ssl, SSL_write(ssl, bb.data(), bb.len));
            LOGD(DSSL, "SSL_write %d bytes\n", (int)ret);
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
void SslRWerBase<T>::dump_status(Dumper dp, void *param) {
    dp(param, "SslRWer <%d> (%s): %s\nrlen: %zu, wlen: %zu, stats: %d, event: %s\n",
       this->getFd(), this->getPeer(), SSL_state_string_long(ssl),
       this->rlength(0), this->wbuff.length(),
       (int)this->getStats(), events_string[(int)this->getEvents()]);
}

int SslRWer<StreamRWer>::fill_in_bio() {
    char buff[BUF_LEN];
    while(true) {
        ssize_t ret = read(this->getFd(), buff, sizeof(buff));
        LOGD(DSSL, "read %d bytes from fd\n", (int)ret);
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
