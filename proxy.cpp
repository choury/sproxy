#include <openssl/err.h>
#include <string>
#include <set>

#include "proxy.h"
#include "proxy_spdy.h"
#include "guest.h"



Proxy::Proxy(Proxy* copy) {
    *this=*copy;
    bindex.del(copy,bindex.query(copy));
    bindex.add(this,bindex.query(copy));

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    copy->ctx=nullptr;
    copy->ssl=nullptr;
    copy->fd=0;
    delete copy;
}



Proxy::Proxy(HttpReqHeader &req,Guest *guest):Host(req,guest,SHOST,SPORT) {}


Host* Proxy::getproxy(HttpReqHeader &req,Guest* guest) {
    if(proxy_spdy) {
        return Proxy_spdy::getproxy_spdy(req,guest);
    }
    Host *exist=(Host *)bindex.query(guest);
    if (dynamic_cast<Proxy*>(exist)) {
        exist->Request(req,guest);
        guest->connected();
        return exist;
    }
    if (exist != NULL) {
        exist->clean(guest);
    }

    return new Proxy(req,guest);

}


void Proxy::Request(HttpReqHeader &req,Guest *guest) {
    writelen+=req.getstring(wbuff+writelen);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    this->req=req;
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
    switch(error) {
    case SSL_ERROR_WANT_READ:
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_WANT_WRITE:
        event.events = EPOLLOUT|EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_ZERO_RETURN:
        break;
    case SSL_ERROR_SYSCALL:
        LOGE("%s:%s\n",s, strerror(errno));
        break;
    default:
        LOGE("%s:%s\n",s, ERR_error_string(error, NULL));
    }
    return 1;
}


static int select_next_proto_cb(SSL* ssl,
                                unsigned char **out, unsigned char *outlen,
                                const unsigned char *in, unsigned int inlen,
                                void *arg)
{
    (void)ssl;
    std::set<std::string> proset;
    while(*in) {
        uint8_t len=*in++;
        proset.insert(std::string((const char*)in,len));
        in+=len;
    }
    if( proset.count("spdy/3.1")) {
        *out=(unsigned char*)"spdy/3.1";
        *outlen=strlen((char*)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    if(proset.count("http/1.1")) {
        *out=(unsigned char*)"http/1.1";
        *outlen=strlen((char*)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}


void Proxy::waitconnectHE(uint32_t events) {
    Guest *guest=(Guest *)bindex.query(this);
    if( guest == NULL) {
        clean(this);
        return;
    }
    if (events & EPOLLOUT) {
        int error;
        socklen_t len=sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            perror("proxy getsokopt");
            clean(this);
            return;
        }

        if (error != 0) {
            LOGE( "connect to proxy:%s\n", strerror(error));
            if(connect()<0) {
                clean(this);
            }
            return;
        }
        ctx = SSL_CTX_new(SSLv23_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            clean(this);
            return;
        }
        SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3); //去除支持SSLv2 SSLv3
        SSL_CTX_set_next_proto_select_cb(ctx,select_next_proto_cb,this);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        handleEvent=(void (Con::*)(uint32_t))&Proxy::shakehandHE;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("host unkown error: %s\n",strerror(errno));
        clean(this);
    }
}


void Proxy::shakehandHE(uint32_t events) {
    Guest *guest=(Guest *)bindex.query(this);
    if( guest == NULL) {
        clean(this);
        return;
    }
    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = SSL_connect(ssl);
        if (ret != 1) {
            if(showerrinfo(ret,"ssl connect error")) {
                clean(this);
            }
            return;
        }
        
        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN |EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        handleEvent=(void (Con::*)(uint32_t))&Proxy::defaultHE;

        const unsigned char *data;
        unsigned int len;
        SSL_get0_next_proto_negotiated(ssl,&data,&len);
        if(data && strncasecmp((const char*)data,"spdy/3.1",len)==0) {
            proxy_spdy=new Proxy_spdy(this,guest);
            return;
        }
        
        writelen= req.getstring(wbuff);
        guest->connected();
        return;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("proxy unkown error: %s\n",strerror(errno));
        clean(this);
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
