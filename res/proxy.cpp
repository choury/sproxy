#include "proxy.h"
//#include "proxy2.h"
#include "req/requester.h"
#include "misc/dtls.h"
#include "misc/job.h"

#include <openssl/err.h>

Proxy::Proxy(const char* hostname, uint16_t port, Protocol protocol): 
        Host(hostname, port, protocol)
{
    rwer = new SRWer();
}

Responser* Proxy::getproxy(HttpReqHeader* req, Responser* responser_ptr) {
#if 0
    if (proxy2) {
        return proxy2;
    }
    if(SPROT == Protocol::RUDP){
        return new Proxy2(SHOST, SPORT);
    }
#endif
    Proxy *proxy = dynamic_cast<Proxy *>(responser_ptr);
    if(req->ismethod("CONNECT") || req->ismethod("SEND")){
        return new Proxy(SHOST, SPORT, SPROT);
    }
    if(proxy){
        return proxy;
    }
    return new Proxy(SHOST, SPORT, SPROT);
}

static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";

#if 0

void Proxy::waitconnectHE(uint32_t events) {
    int       error = 0;
    socklen_t errlen = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) != 0) {
        LOGE("(%s): proxy getsokopt error: %s\n", hostname, strerror(errno));
        return deleteLater(INTERNAL_ERR);
    }
    if (error != 0){
        LOGE("(%s): connect to proxy error: %s\n", hostname, strerror(error));
        return connect();
    }

    if (events & EPOLLOUT) {
        if(protocol == Protocol::TCP){
            ctx = SSL_CTX_new(SSLv23_client_method());
            if (ctx == NULL) {
                LOGE("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
                return deleteLater(INTERNAL_ERR);
            }
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
            SSL_CTX_set_read_ahead(ctx, 1);
            
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            this->ssl = new Ssl(ssl);
        }else{
            ctx = SSL_CTX_new(DTLS_client_method());
            if (ctx == NULL) {
                LOGE("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
                return deleteLater(INTERNAL_ERR);
            }
            SSL *ssl = SSL_new(ctx);
            BIO* bio = BIO_new_dgram(fd, BIO_NOCLOSE);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addrs.front());
            SSL_set_bio(ssl, bio, bio);
            this->ssl = new Dtls(ssl);
        }
#ifdef __ANDROID__
        if (SSL_CTX_load_verify_locations(ctx, cafile, "/etc/security/cacerts/") != 1)
#else
        if (SSL_CTX_load_verify_locations(ctx, cafile, "/etc/ssl/certs/") != 1)
#endif
            LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
            LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        ssl->set_hostname(SHOST, verify_host_callback);
        
        if(use_http2){
            ssl->set_alpn(alpn_protos_string, sizeof(alpn_protos_string)-1);
        }
        
        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Proxy::shakehandHE;
    }
}

void Proxy::shakehandHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): proxy unkown error: %s\n", hostname, strerror(error));
        }
        return deleteLater(INTERNAL_ERR);
    }

    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = ssl->connect();
        if (ret != 1) {
            if (errno != EAGAIN) {
                LOGE("(%s): ssl connect error:%s\n", hostname, strerror(errno));
                deleteLater(SSL_SHAKEHAND_ERR);
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
            if(req){
                Requester* req_ptr = req->header->src;
                void*      req_index = req->header->index;
                req_ptr->transfer(req_index, new_proxy, new_proxy->request(req));
                delete req;
                req = nullptr;
            }
            this->discard();
            return deleteLater(PEER_LOST_ERR);
        }else{
            if(protocol == Protocol::UDP){
                LOGE("Warning: Use http1.1 on dtls!\n");
            }
            updateEpoll(EPOLLIN | EPOLLOUT);
            handleEvent = (void (Con::*)(uint32_t))&Proxy::defaultHE;
        }
        del_delayjob((job_func)con_timeout, this);
    }
}
#endif

void Proxy::discard() {
    ssl = nullptr;
    ctx = nullptr;
    Host::discard();
}

Proxy::~Proxy() {
    if (ssl) {
        delete ssl;
    }
    if (ctx){
        SSL_CTX_free(ctx);
    }
}
