#include "proxy.h"

#include <set>

#include <openssl/err.h>

#define PROXYERRTIP     "HTTP/1.0 504 Gateway Timeout" CRLF CRLF\
                        "Connect to the proxy failed, you can try again, or switch to another proxy"
                        
#define SSLERRTIP       "HTTP/1.0 502 Bad Gateway" CRLF CRLF\
                        "Ssl shakehand error, you can try again, or switch to another proxy"


Proxy::Proxy(HttpReqHeader &req, Guest *guest):Host(req, guest, SHOST, SPORT) {}


Host* Proxy::getproxy(HttpReqHeader &req, Guest* guest) {
    Host *exist = (Host *)queryconnect(guest);
    if (dynamic_cast<Proxy*>(exist)) {
        exist->Request(req, true);
        return exist;
    }
    if (exist) {
        exist->clean(nullptr);
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
    epoll_event event;
    event.data.ptr = this;
    int error = SSL_get_error(ssl, ret);
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
    return 1;
}


static int select_alpn_cb(SSL* ssl,
                           const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    std::set<std::string> proset;
    while (*in) {
        uint8_t len = *in++;
        proset.insert(std::string((const char*)in, len));
        in+= len;
    }
    if (proset.count("http/1.1")) {
        *out = (unsigned char*)"http/1.1";
        *outlen = strlen((char*)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

#define NEXT_PROTO_STRING \
    "\x8""http/1.1" \
    "\x2""h2"


void Proxy::waitconnectHE(uint32_t events) {
    connectset.del(this);
    Guest *guest = (Guest *)queryconnect(this);
    if (guest == nullptr) {
        clean(this);
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
        SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, this);

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
        destory(PROXYERRTIP);
    }
}


void Proxy::shakehandHE(uint32_t events) {
    Guest *guest = (Guest *)queryconnect(this);
    if (guest == nullptr) {
        clean(this);
        return;
    }
    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = SSL_connect(ssl);
        if (ret != 1) {
            if (showerrinfo(ret, "ssl connect error")) {
                destory(SSLERRTIP);
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
        SSL_get0_next_proto_negotiated(ssl, &data, &len);
        if (data && strncasecmp((const char*)data, "spdy/3.1", len) == 0) {
        }
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("proxy unkown error: %s\n", strerror(errno));
        destory(SSLERRTIP);
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

