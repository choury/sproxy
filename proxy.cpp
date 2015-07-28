#include "proxy.h"
#include "proxy2.h"

#include <openssl/err.h>

extern std::map<Host*,time_t> connectmap;

Proxy::Proxy(HttpReqHeader &req, Guest *guest):Host(req, guest, SHOST, SPORT) {}


Host* Proxy::getproxy(HttpReqHeader &req, Guest* guest) {
    if (proxy2) {
        proxy2->Request(guest, req, true);
        return proxy2;
    }
    Host *exist = (Host *)queryconnect(guest);
    if (dynamic_cast<Proxy*>(exist)) {
        exist->Request(guest, req, true);
        return exist;
    }
    if (exist) {
        exist->clean(nullptr, NOERROR);
    }

    return new Proxy(req, guest);
}


ssize_t Proxy::Write() {
    ssize_t ret = SSL_write(ssl, wbuff, writelen);

    if (ret <= 0) {
        return ret;
    }

    if ((size_t)ret != writelen) {
        memmove(wbuff, wbuff + ret, writelen - ret);
        writelen -= ret;
    } else {
        writelen = 0;
    }

    return ret;
}

ssize_t Proxy::Read(void* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


int Proxy::showerrinfo(int ret, const char* s) {
    if(ret <= 0){
        epoll_event event;
        event.data.ptr = this;
        int error = SSL_get_error(ssl, ret);
        ERR_clear_error();
        switch (error) {
        case SSL_ERROR_WANT_READ:
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            return 0;
        case SSL_ERROR_WANT_WRITE:
            event.events = EPOLLIN|EPOLLOUT;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            break;
        case SSL_ERROR_SYSCALL:
            LOGE("%s:%s\n", s, strerror(errno));
            break;
        default:
            LOGE("%s:%s\n", s, ERR_error_string(error, NULL));
        }
    } else {
        LOGE("%s:%d\n", s, ret);
    }
    return 1;
}


static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";


void Proxy::waitconnectHE(uint32_t events) {
    connectmap.erase(this);
    Guest *guest = (Guest *)queryconnect(this);
    if (guest == nullptr) {
        clean(this, PEER_LOST_ERR);
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
            LOGE("proxy getsokopt error: %s\n", strerror(errno));
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
        SSL_CTX_set_alpn_protos(ctx, alpn_protos_string, sizeof(alpn_protos_string)-1);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        handleEvent = (void (Con::*)(uint32_t))&Proxy::shakehandHE;
    }
    return;
reconnect:
    if (connect() < 0) {
        destory(H502);
    }
}


void Proxy::shakehandHE(uint32_t events) {
    Guest *guest = (Guest *)queryconnect(this);
    if (guest == nullptr) {
        clean(this, PEER_LOST_ERR);
        return;
    }
    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = SSL_connect(ssl);
        if (ret != 1) {
            if (showerrinfo(ret, "ssl connect error")) {
                destory(H502);
            }
            return;
        }

        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN |EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        handleEvent = (void (Con::*)(uint32_t))&Proxy::defaultHE;

        const unsigned char *data;
        unsigned int len;
        SSL_get0_alpn_selected(ssl, &data, &len);
        if (data && strncasecmp((const char*)data, "h2", len) == 0) {
            if(!proxy2){
                proxy2 = new Proxy2(fd, ssl, ctx);
                proxy2->init();
                proxy2->Request(guest, req, true);
                fd  = 0;
                ssl = nullptr;
                ctx = nullptr;
                disconnect(nullptr, NOERROR);
                delete this;
            }
        }
        return;
        
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("proxy unkown error: %s\n", strerror(errno));
        destory(H502);
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

int Proxy::showstatus(char* buff){
    int wlen,len;
    sprintf(buff, "%s ##(proxy)%n", req.url, &wlen);
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
    
    sprintf(buff+wlen, " %s\r\n%n", status, &len);
    return wlen + len;
}

