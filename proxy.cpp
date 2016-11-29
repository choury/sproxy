#include "proxy.h"
#include "proxy2.h"

#include <openssl/err.h>
#include "requester.h"
#include "dtls.h"


extern std::map<Host*,time_t> connectmap;

Proxy::Proxy(const char* hostname, uint16_t port, Protocol protocol): 
        Host(hostname, port, protocol), req(nullptr, this) {

}

Responser* Proxy::getproxy(HttpReqHeader &req, Responser* responser_ptr, uint32_t id) {
    Host *exist = dynamic_cast<Host *>(responser_ptr);
    Proxy *proxy = dynamic_cast<Proxy *>(exist);
    if (proxy) {
        return proxy;
    }
    
    if (exist) {
        exist->clean(NOERROR, id); //只有exist是host才会走到这里
    }
    
    if (proxy2 && proxy2->bufleft(0) >= 32 * 1024) {
        return proxy2;
    }
    return new Proxy(SHOST, SPORT, SPROT);
}

ssize_t Proxy::Read(void* buff, size_t size) {
    return ssl->read(buff, size);
}


ssize_t Proxy::Write(const void *buff, size_t size) {
    return ssl->write(buff, size);
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
        LOG("cert depth=%d:%s\n", depth, buf);
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

static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";


void Proxy::waitconnectHE(uint32_t events) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, 0);
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): connect to proxy error: %s\n",
                 requester_ptr->getsrc(), strerror(error));
        }
        goto reconnect;
    }

    if (events & EPOLLOUT) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("(%s): proxy getsokopt error: %m\n", requester_ptr->getsrc());
            goto reconnect;
        }
            
        if (error != 0) {
            LOGE("(%s): connect to proxy:%s\n",
                 requester_ptr->getsrc(), strerror(error));
            goto reconnect;
        }
        if(protocol == Protocol::TCP){
            ctx = SSL_CTX_new(SSLv23_client_method());
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                goto reconnect;
            }
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
            SSL_CTX_set_read_ahead(ctx, 1);
            
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            this->ssl = new Ssl(ssl);
        }else{
            ctx = SSL_CTX_new(DTLS_client_method());
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                goto reconnect;
            }
            SSL *ssl = SSL_new(ctx);
            BIO* bio = BIO_new_dgram(fd, BIO_NOCLOSE);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addrs[testedaddr-1]);
            SSL_set_bio(ssl, bio, bio);
            this->ssl = new Dtls(ssl);
        }
        if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs/") != 1)
            ERR_print_errors_fp(stderr);

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
            ERR_print_errors_fp(stderr);
        ssl->set_hostname(SHOST, verify_host_callback);
        
        if(use_http2){
            ssl->set_alpn(alpn_protos_string, sizeof(alpn_protos_string)-1);
        }
        
        if(ssl->is_dtls()){
            add_tick_func(dtls_tick, ssl);
        }
        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Proxy::shakehandHE;
    }
    return;
reconnect:
    if (connect() < 0) {
        clean(CONNECT_ERR, 0);
    }
}


void Proxy::shakehandHE(uint32_t events) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, 0);
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): proxy unkown error: %s\n",
                 requester_ptr->getsrc(), strerror(error));
        }
        clean(SSL_SHAKEHAND_ERR, 0);
        return;
    }

    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = ssl->connect();
        if (ret != 1) {
            if (errno != EAGAIN) {
                LOGE("(%s): ssl connect error:%m\n", requester_ptr->getsrc());
                clean(SSL_SHAKEHAND_ERR, 0);
            }
            return;
        }
        
        const unsigned char *data;
        unsigned int len;
        ssl->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0))
        {
            Proxy2 *new_proxy = new Proxy2(fd, ctx,ssl);
            new_proxy->init();
            requester_ptr->ResetResponser(new_proxy, req.http_id);
            new_proxy->request(std::move(req));
            if(!proxy2){
                proxy2 = new_proxy;
            }
            this->discard();
            clean(NOERROR, 0);
        }else{
            if(protocol == Protocol::UDP){
                LOGE("Warning: Use http1.1 on dtls!\n");
            }
            updateEpoll(EPOLLIN | EPOLLOUT);
            handleEvent = (void (Con::*)(uint32_t))&Proxy::defaultHE;
        }
        connectmap.erase(this);
        return;
        
    }
}

uint32_t Proxy::request(HttpReqHeader&& req) {
    if(use_http2 && (hostname[0] == 0 || connectmap.count(this))){
        this->req = req;
    }
    return Host::request(std::move(req));
}

void Proxy::discard() {
    del_tick_func(dtls_tick, ssl);
    ssl = nullptr;
    ctx = nullptr;
    Host::discard();
}



Proxy::~Proxy() {
    if (ssl) {
        del_tick_func(dtls_tick, ssl);
        delete ssl;
    }
    if (ctx){
        SSL_CTX_free(ctx);
    }
}
