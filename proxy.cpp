#include "proxy.h"
#include "proxy2.h"

#include <openssl/err.h>
#include "requester.h"
#include "dtls.h"


extern int use_http2;
extern std::map<Host*,time_t> connectmap;

Proxy::Proxy(const char* hostname, uint16_t port, Protocol protocol): Host(hostname, port, protocol) {

}

Responser* Proxy::getproxy(HttpReqHeader &req, Responser* responser_ptr) {
    Host *exist = dynamic_cast<Host *>(responser_ptr);
    Proxy *proxy = dynamic_cast<Proxy *>(exist);
    if (proxy) {
        proxy->request(req);
        return proxy;
    }
    
    if (exist) {
        exist->ResetRequester(nullptr);
        exist->clean(NOERROR, exist); //只有exist是host才会走到这里
    }
    
    if (proxy2 && proxy2->bufleft(nullptr) >= 32 * 1024) {
        proxy2->request(req);
        return proxy2;
    }
    proxy = new Proxy(SHOST, SPORT, SPROT);
    proxy->request(req);
    return proxy;
}

ssize_t Proxy::Read(void* buff, size_t size) {
    return ssl->read(buff, size);
}


ssize_t Proxy::Write(const void *buff, size_t size) {
    return ssl->write(buff, size);
}


static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";


void Proxy::waitconnectHE(uint32_t events) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("connect to proxy error: %s\n", strerror(error));
        }
        goto reconnect;
    }

    if (events & EPOLLOUT) {
        int error;
        socklen_t len = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("proxy getsokopt error: %m\n");
            goto reconnect;
        }
            
        if (error != 0) {
            LOGE("connect to proxy:%s\n", strerror(error));
            goto reconnect;
        }
        if(protocol == TCP){
            ctx = SSL_CTX_new(SSLv23_client_method());
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                goto reconnect;
            }
            SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
            SSL_CTX_set_read_ahead(ctx, 1);
            
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);
            SSL_set_tlsext_host_name(ssl, hostname);
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
        clean(CONNECT_ERR, this);
    }
}


void Proxy::shakehandHE(uint32_t events) {
    if (requester_ptr == NULL) {
        clean(PEER_LOST_ERR, this);
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("proxy unkown error: %s\n", strerror(error));
        }
        clean(SSL_SHAKEHAND_ERR, this);
        return;
    }

    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = ssl->connect();
        if (ret != 1) {
            if (errno != EAGAIN) {
                LOGE("ssl connect error:%m\n");
                clean(SSL_SHAKEHAND_ERR, this);
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
            new_proxy->request(req);
            requester_ptr->ResetResponser(new_proxy);
            if(!proxy2){
                proxy2 = new_proxy;
            }
            this->discard();
            clean(NOERROR, this);
        }else{
            if(protocol == UDP){
                LOGE("Warning: Use http1.1 on dtls!\n");
            }
            updateEpoll(EPOLLIN | EPOLLOUT);
            handleEvent = (void (Con::*)(uint32_t))&Proxy::defaultHE;
        }
        connectmap.erase(this);
        return;
        
    }
}

void Proxy::request(HttpReqHeader& req)
{
    this->req = req;
    return Host::request(req);
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
