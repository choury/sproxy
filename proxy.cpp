#include "proxy.h"
#include "proxy2.h"
#include "guest.h"

#include <openssl/err.h>


extern std::map<Host*,time_t> connectmap;


Proxy::Proxy(Proxy&& copy): Host(std::move(copy)), ssl(copy.ssl), ctx(copy.ctx) {
    copy.ssl = nullptr;
    copy.ctx = nullptr;
}

Proxy::Proxy(const char* hostname, uint16_t port): Host(hostname, port) {

}

Ptr Proxy::getproxy(HttpReqHeader &req, Ptr responser_ptr) {
    Host *exist = dynamic_cast<Host *>(responser_ptr.get());
    if (dynamic_cast<Proxy*>(exist)) {
        return exist->request(req);
    }
    
    if (exist) {
        exist->clean(NOERROR, nullptr); //只有exist是host才会走到这里
    }
    
    if (proxy2 && proxy2->bufleft(nullptr) >= 32 * 1024) {
        return proxy2->request(req);
    }

    return (new Proxy(SHOST, SPORT))->request(req);
}

ssize_t Proxy::Read(void* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


ssize_t Proxy::Write(const void *buff, size_t size) {
    return SSL_write(ssl, buff, size);
}

int Proxy::showerrinfo(int ret, const char* s) {
    if(ret <= 0){
        int error = SSL_get_error(ssl, ret);
        switch (error) {
        case SSL_ERROR_WANT_READ:
            updateEpoll(EPOLLIN);
            return 0;
        case SSL_ERROR_WANT_WRITE:
            updateEpoll(EPOLLIN | EPOLLOUT);
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            break;
        case SSL_ERROR_SYSCALL:
            error = ERR_get_error();
            if (error == 0 && ret == 0){
                LOGE("%s: the connection was lost\n", s);
            }else if (error == 0 && ret == -1){
                LOGE("%s:%m\n", s);
            }else{
                LOGE("%s:%s\n", s, ERR_error_string(error, NULL));
            }
            break;
        default:
            LOGE("%s:%s\n", s, ERR_error_string(ERR_get_error(), NULL));
        }
    } else {
        LOGE("%s:%d\n", s, ret);
    }
    ERR_clear_error();
    return 1;
}


static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";


void Proxy::waitconnectHE(uint32_t events) {
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
        ctx = SSL_CTX_new(SSLv23_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            goto reconnect;
        }
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
        SSL_CTX_set_read_ahead(ctx, 1);
        if(proxy2 == nullptr)
            SSL_CTX_set_alpn_protos(ctx, alpn_protos_string, sizeof(alpn_protos_string)-1);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        SSL_set_tlsext_host_name(ssl, hostname);

        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Proxy::shakehandHE;
        connectmap.erase(this);
    }
    return;
reconnect:
    if (connect() < 0) {
        clean(CONNECT_ERR, nullptr);
    }
}


void Proxy::shakehandHE(uint32_t events) {
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
        int ret = SSL_connect(ssl);
        if (ret != 1) {
            if (showerrinfo(ret, "ssl connect error")) {
                clean(SSL_SHAKEHAND_ERR, this);
            }
            return;
        }

        updateEpoll(EPOLLIN | EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Proxy::defaultHE;
        
        const unsigned char *data;
        unsigned int len;
        SSL_get0_alpn_selected(ssl, &data, &len);
        if (data && strncasecmp((const char*)data, "h2", len) == 0) {
            Proxy2 *new_proxy = new Proxy2(std::move(*this));
            new_proxy->init();
            new_proxy->request(req);
            if(!proxy2){
                proxy2 = new_proxy;
            }
            clean(NOERROR, nullptr);
        }
        return;
        
    }
}

Proxy::~Proxy() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

/*
int Proxy::showstatus(char* buff, Peer*){
    int len;
    len = sprintf(buff, "%s ##(proxy)", req.url);
    const char *status;
    if(handleEvent ==  nullptr)
        status = "Waiting dns";
    else if(handleEvent == (void (Con::*)(uint32_t))&Proxy::waitconnectHE)
        status = "connecting...";
    else if(handleEvent == (void (Con::*)(uint32_t))&Proxy::shakehandHE)
        status = "ssl shankhand";
    else if(handleEvent == (void (Con::*)(uint32_t))&Proxy::defaultHE)
        status = "transfer data";
    else if(handleEvent == (void (Con::*)(uint32_t))&Proxy::closeHE)
        status = "Waiting close";
    else
        status = "unkown status";
    
    len += sprintf(buff+len, " %s\r\n", status);
    return len;
}
*/
