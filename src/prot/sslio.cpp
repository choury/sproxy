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

SslRWerBase::SslRWerBase(SSL_CTX *ctx) {
    sslStats = SslStats::SslAccepting;
    ssl = SSL_new(ctx);
    SSL_set_accept_state(ssl);

    BIO_set_mem_eof_return(in_bio, -1);
    BIO_set_mem_eof_return(out_bio, -1);
    SSL_set_bio(ssl, in_bio, out_bio);
}

SslRWerBase::SslRWerBase(const char *hostname) {
    sslStats = SslStats::SslConnecting;
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
    set_server_name(hostname);

    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

    /* Enable automatic hostname checks */
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    X509_VERIFY_PARAM_set1_host(param, hostname, strlen(hostname));

    /* Configure a non-zero callback if desired */
    SSL_set_verify(ssl, SSL_VERIFY_PEER, verify_host_callback);
}

SslRWerBase::~SslRWerBase(){
    SSL_free(ssl);
    if(ctx){
        SSL_CTX_free(ctx);
    }
}

void SslRWerBase::sink_out_bio(uint64_t id) {
    while(BIO_ctrl_pending(out_bio)) {
        char buff[BUF_LEN];
        int ret = BIO_read(out_bio, buff, sizeof(buff));
        LOGD(DSSL, "[%s] BIO_read %d bytes\n", server.c_str(), ret);
        if (ret > 0) {
            write(Buffer{std::make_shared<Block>(buff, ret), (size_t)ret, id});
        }
    }
}

int SslRWerBase::sink_in_bio(uint64_t id) {
    char buff[BUF_LEN];
    ERR_clear_error();
    size_t len = std::min(sizeof(buff), bufsize());
    if (len == 0) {
        return 0;
    }
    ssize_t ret = ssl_get_error(ssl, SSL_read(ssl, buff, (int)len));
    LOGD(DSSL, "[%s] SSL_read %d bytes\n", server.c_str(), (int) ret);
    if (ret > 0) {
        onRead(Buffer{std::make_shared<Block>(buff, ret), (size_t) ret, id});
        return 1;
    } else if (ret == 0) {
        sslStats = SslStats::SslEOF;
        return 0;
    } else if (errno != EAGAIN) {
        onError(SSL_SHAKEHAND_ERR, errno);
    }
    return 0;
}

void SslRWerBase::handleData(Buffer&& bb) {
    int ret = BIO_write(in_bio, bb.data(), (int)bb.len);
    LOGD(DSSL, "[%s] BIO_write %d bytes\n", server.c_str(), ret);
    switch(sslStats) {
    case SslStats::Idel:
        //it should set to SslStats::SslAccepting or SslStats::SslConnecting in constructor
        abort();
    case SslStats::SslAccepting:
    case SslStats::SslConnecting:
        do_handshake();
    case SslStats::Established:
        while (sslStats == SslStats::Established && sink_in_bio(bb.id));
        break;
    case SslStats::SslEOF:
        LOGE("[%s] ssl eof, discard all data\n", server.c_str());
        break;
    }
}

void SslRWerBase::sendData(Buffer&& bb) {
    if(bb.len == 0) {
        SSL_shutdown(ssl);
    }else {
        ERR_clear_error();
        while(bb.len > 0) {
            ssize_t ret = ssl_get_error(ssl, SSL_write(ssl, bb.data(), bb.len));
            LOGD(DSSL, "[%s] SSL_write %d/%zd bytes\n", server.c_str(), (int)ret, bb.len);
            if(ret > 0) {
                bb.reserve(ret);
                continue;
            }
            onError(SSL_SHAKEHAND_ERR, errno);
            return;
        }
    }
    sink_out_bio(bb.id);
}

void SslRWerBase::do_handshake() {
    ERR_clear_error();
    if(ssl_get_error(ssl, SSL_do_handshake(ssl)) == 1){
        sslStats = SslStats::Established;
        LOGD(DSSL, "[%s] ssl handshake success\n", server.c_str());
        onConnected();
    }else if(errno != EAGAIN){
        int error = errno;
        LOGE("[%s]: ssl %s error:%s\n", server.c_str(), ctx?"connect":"accept", strerror(error));
        onError(SSL_SHAKEHAND_ERR, error);
    }
    sink_out_bio(0);
}

bool SslRWerBase::isConnected() {
    return sslStats == SslStats::Established;
}

bool SslRWerBase::isEof() {
    return sslStats == SslStats::SslEOF;
}

void SslRWerBase::get_alpn(const unsigned char **s, unsigned int * len){
    SSL_get0_alpn_selected(ssl, s, len);
}

int SslRWerBase::set_alpn(const unsigned char *s, unsigned int len){
    ERR_clear_error();
    return ssl_get_error(ssl, SSL_set_alpn_protos(ssl, s, len));
}

void SslRWerBase::set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg){
//    SSL_callback_ctrl(ssl, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, cb);
    SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
    SSL_CTX_set_tlsext_servername_callback(ctx, cb);
    SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}

void SslRWerBase::set_server_name(const std::string& arg) {
    server = arg;
    SSL_set_app_data(ssl, server.c_str());
}

void SslRWerBase::dump(Dumper dp, void *param) {
    dp(param, "Ssl (%s): rbio: %zu, wbio: %zu, sslStats: %d (%s)\n",
       server.c_str(), BIO_ctrl_pending(in_bio), BIO_ctrl_pending(out_bio),
       (int)sslStats, SSL_state_string_long(ssl));
}

SslRWer::SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
        SslRWerBase(hostname), StreamRWer(hostname, port, protocol, std::move(errorCB))
{
        assert(this->protocol == Protocol::TCP);
}

void SslRWer::write(Buffer&& bb) {
    LOGD(DSSL, "[%s] send %zd bytes to fd %d\n", server.c_str(), bb.len, getFd());
    addEvents(RW_EVENT::WRITE);
    wbuff.push(wbuff.end(), std::move(bb));
}

void SslMer::write(Buffer&& bb) {
    LOGD(DSSL, "[%s] send %zd bytes to mem\n", server.c_str(), bb.len);
    addEvents(RW_EVENT::WRITE);
    wbuff.push(wbuff.end(), std::move(bb));
}

void SslRWer::onRead(Buffer&& bb) {
    rb.put(bb.data(), bb.len);
}

void SslMer::onRead(Buffer&& bb) {
    rb.put(bb.data(), bb.len);
}

void SslRWer::onConnected() {
    connected(addrs.front());
}

void SslMer::onConnected() {
    connected({});
}

void SslRWer::onError(int type, int code) {
    ErrorHE(type, code);
}

void SslMer::onError(int type, int code) {
    ErrorHE(type, code);
}

void SslRWer::ReadData() {
    assert(stats == RWerStats::Connected);
    char buff[BUF_LEN];
    while(true) {
        size_t left = rb.cap();
        if (left == 0) {
            break;
        }
        ssize_t ret = read(this->getFd(), buff, std::min(sizeof(buff), left));
        LOGD(DSSL, "[%s] read %d bytes from fd %d\n", server.c_str(), (int)ret, getFd());
        if (ret > 0) {
            handleData(Buffer{std::make_shared<Block>(buff, ret), (size_t)ret, 0});
            StreamRWer::ConsumeRData(0);
            continue;
        } else if (ret == 0) {
            stats = RWerStats::ReadEOF;
            delEvents(RW_EVENT::READ);
            break;
        } else if (errno == EAGAIN) {
            break;
        }
        ErrorHE(SOCKET_ERR, errno);
        return;
    }
    StreamRWer::ConsumeRData(0);
}

void SslRWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR)) {
        int error = this->checkSocket(__PRETTY_FUNCTION__ );
        this->con_failed_job = UpdateJob(std::move(this->con_failed_job),
                                         ([this, error]{connectFailed(error);}), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        LOGD(DSSL, "[%s] connected from fd %d, start handshark\n", server.c_str(), getFd());
        assert(!this->addrs.empty());
        setEvents(RW_EVENT::READWRITE);
        stats = RWerStats::Connected;
        this->con_failed_job = UpdateJob(std::move(this->con_failed_job),
                                         [this]{connectFailed(ETIMEDOUT);}, 2000);
        handleEvent = (void (Ep::*)(RW_EVENT))&SslRWer::defaultHE;
        do_handshake();
    }
}

void SslRWer::Send(Buffer&& bb) {
    assert((this->flags & RWER_SHUTDOWN) == 0);
    if(this->stats == RWerStats::Error) {
        return;
    }
    sendData(std::move(bb));
}

void SslMer::Send(Buffer&& bb) {
    assert((this->flags & RWER_SHUTDOWN) == 0);
    if(this->stats == RWerStats::Error) {
        return;
    }
    sendData(std::move(bb));
}


void SslMer::push_data(const Buffer& bb) {
    if(isEof()) {
        //shutdown by ssl, discard all data after that
        return;
    }
    LOGD(DSSL, "[%s] read %d bytes from peer\n", server.c_str(), (int)bb.len);
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        handleData(Buffer{bb});
    }
    MemRWer::ConsumeRData(bb.id);
}

void SslRWer::dump_status(Dumper dp, void *param) {
    SocketRWer::dump_status(dp, param);
    dump(dp, param);
}

void SslMer::dump_status(Dumper dp, void *param) {
    MemRWer::dump_status(dp, param);
    dump(dp, param);
}
