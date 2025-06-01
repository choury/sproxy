#include "sslio.h"
#include "prot/rwer.h"
#include "prot/tls.h"
#include "misc/hook.h"

#include <openssl/err.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#if __ANDROID__
extern std::string getExternalFilesDir();
#endif

static SSL_CTX* client_ctx = nullptr;

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
    if(client_ctx == nullptr) {
        client_ctx = SSL_CTX_new(SSLv23_client_method());
        if (client_ctx == nullptr) {
            LOGF("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        }
        SSL_CTX_set_keylog_callback(client_ctx, keylog_write_line);
#if __ANDROID__
        if (SSL_CTX_load_verify_locations(client_ctx, (getExternalFilesDir() + CABUNDLE).c_str(), "/etc/security/cacerts/") != 1)
#else
        if (SSL_CTX_load_verify_locations(client_ctx, CABUNDLE, "/etc/ssl/certs/") != 1)
#endif
            LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));


        if (SSL_CTX_set_default_verify_paths(client_ctx) != 1)
            LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));

    }

    ssl = SSL_new(client_ctx);
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
}

void SslRWerBase::sink_out_bio(uint64_t id) {
    Block buff(BUF_LEN);
    size_t offset = 0;
    while(BIO_ctrl_pending(out_bio) && offset < BUF_LEN) {
        int ret = BIO_read(out_bio, (char*)buff.data() + offset, BUF_LEN - offset);
        LOGD(DSSL, "[%s] BIO_read %d bytes\n", server.c_str(), ret);
        if (ret > 0) {
            offset += ret;
        } else {
            break;
        }
    }
    HOOK_FUNC(this, out_bio, buff, offset);
    if(offset > 0) {
        write(Buffer{std::move(buff), (size_t)offset, id});
    }
    if(offset == BUF_LEN) {
        sink_out_bio(id);
    }
}

int SslRWerBase::sink_in_bio(uint64_t id) {
    Block buff(BUF_LEN);
    ERR_clear_error();
    size_t len = std::min((size_t)BUF_LEN, bufsize());
    if (len == 0) {
        return 0;
    }
    ssize_t ret = ssl_get_error(ssl, SSL_read(ssl, buff.data(), (int)len));
    LOGD(DSSL, "[%s] SSL_read %d bytes\n", server.c_str(), (int) ret);
    HOOK_FUNC(this, in_bio, buff, ret);
    if (ret > 0) {
        onRead(Buffer{std::move(buff), (size_t) ret, id});
        return 1;
    } else if (ret == 0) {
        sslStats = SslStats::SslEOF;
        return 0;
    } else if (errno != EAGAIN) {
        sslStats = SslStats::SslError;
        onError(SSL_SHAKEHAND_ERR, errno);
    }
    return 0;
}

void SslRWerBase::handleData(const void* data, size_t len) {
    HOOK_FUNC(this, data, len);
    if(len > 0) {
        int ret = BIO_write(in_bio, data, (int)len);
        LOGD(DSSL, "[%s] BIO_write %d bytes\n", server.c_str(), ret);
        HOOK_FUNC(this, in_bio, ret);
    } else {
        LOGD(DSSL, "[%s] handleData with nullptr\n", server.c_str());
    }
    switch(sslStats) {
    case SslStats::Idel:
        //it should set to SslStats::SslAccepting or SslStats::SslConnecting in constructor
        abort();
    case SslStats::SslAccepting:
    case SslStats::SslConnecting:
        do_handshake();
    case SslStats::Established:
        while (sslStats == SslStats::Established && sink_in_bio(0));
        break;
    case SslStats::SslEOF: case SslStats::SslError:
        LOGE("[%s] ssl eof/error, discard all data\n", server.c_str());
        break;
    }
}

void SslRWerBase::sendData(Buffer&& bb) {
    HOOK_FUNC(this, bb);
    if(bb.len == 0) {
        LOGD(DSSL, "[%s] SSL_shutdown\n", server.c_str());
        SSL_shutdown(ssl);
    }else {
        ERR_clear_error();
        while(bb.len > 0) {
            ssize_t ret = ssl_get_error(ssl, SSL_write(ssl, bb.data(), bb.len));
            LOGD(DSSL, "[%s] SSL_write %d/%zd bytes\n", server.c_str(), (int)ret, bb.len);
            HOOK_FUNC(this, bb, ret);
            if(ret > 0) {
                bb.reserve(ret);
                continue;
            }
            sslStats = SslStats::SslError;
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
        sslStats = SslStats::SslError;
        int error = errno;
        LOGE("[%s]: ssl %s error:%s\n", server.c_str(), SSL_is_server(ssl)?"accept":"connect", strerror(error));
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

SslRWer::SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::shared_ptr<IRWerCallback> cb):
        SslRWerBase(hostname), StreamRWer(hostname, port, protocol, std::move(cb))
{
        assert(this->protocol == Protocol::TCP);
}

void SslRWer::write(Buffer&& bb) {
    LOGD(DSSL, "[%s] send %zd bytes to fd %d, id: %" PRIu64"\n", server.c_str(), bb.len, getFd(), bb.id);
    addEvents(RW_EVENT::WRITE);
    wlen += bb.len;
    wbuff.emplace_back(std::move(bb));
}

void SslMer::write(Buffer&& bb) {
    //bb.id = id;
    LOGD(DSSL, "[%s] send %zd bytes to mem, id: %" PRIu64"\n", server.c_str(), bb.len, bb.id);
    addEvents(RW_EVENT::WRITE);
    wlen += bb.len;
    wbuff.emplace_back(std::move(bb));
}

void SslRWer::onRead(Buffer&& bb) {
    rb.put(bb.data(), bb.len);
}

void SslMer::onRead(Buffer&& bb) {
    rlen += bb.len;
    rb.emplace_back(std::move(bb));
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
        LOGD(DSSL, "[%s] read %d/%zd bytes from fd %d\n", server.c_str(), (int)ret, left, getFd());
        if (ret > 0) {
            handleData(buff, (size_t)ret);
            //StreamRWer::ConsumeRData(0);
            continue;
        } else if (ret == 0) {
            if(BIO_ctrl_pending(in_bio) > 0) {
                handleData(nullptr, 0);
            }else{
                stats = RWerStats::ReadEOF;
                delEvents(RW_EVENT::READ);
            }
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
    if(this->stats == RWerStats::Error || sslStats == SslStats::SslError) {
        return;
    }
    sendData(std::move(bb));
}

void SslMer::Send(Buffer&& bb) {
    assert((this->flags & RWER_SHUTDOWN) == 0);
    if(this->stats == RWerStats::Error || sslStats == SslStats::SslError) {
        return;
    }
    sendData(std::move(bb));
}


void SslMer::push_data(Buffer&& bb) {
    assert(stats != RWerStats::ReadEOF);
    if(isEof()) {
        //shutdown by ssl, discard all data after that
        return;
    }
    LOGD(DSSL, "[%s] read %d bytes from peer\n", server.c_str(), (int)bb.len);
    if(bb.len == 0){
        stats = RWerStats::ReadEOF;
    } else {
        handleData(bb.data(), bb.len);
    }
    bb.len = 0;
    addEvents(RW_EVENT::READ);
}

void SslRWer::dump_status(Dumper dp, void *param) {
    SocketRWer::dump_status(dp, param);
    dump(dp, param);
}

void SslMer::dump_status(Dumper dp, void *param) {
    MemRWer::dump_status(dp, param);
    dump(dp, param);
}
