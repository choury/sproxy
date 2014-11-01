#include <sys/epoll.h>
#include <openssl/err.h>

#include "proxy.h"
#include "guest.h"



Proxy::Proxy(int efd,Guest *guest):Host(efd,guest,SHOST,SPORT) {}


Host* Proxy::getproxy(Host* exist, int efd, Guest* guest) {
    if (exist == NULL) {
        return new Proxy(efd, guest);
    } else if (dynamic_cast<Proxy*>(exist)) {
        return exist;
    } else {
        Proxy* newproxy = new Proxy(efd, guest);
        exist->clean();
        return newproxy;
    }
}

int Proxy::Write() {
    int ret = SSL_write(ssl, wbuff, write_len);

    if (ret <= 0) {
        return ret;
    }

    if (ret != write_len) {
        memmove(wbuff, wbuff + ret, write_len - ret);
        write_len -= ret;
    } else {
        write_len = 0;
    }

    return ret;
}

int Proxy::Read(char* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


int Proxy::showerrinfo(int ret, const char* s){
    epoll_event event;
    event.data.ptr = this;
    int error = SSL_get_error(ssl, ret);
    switch(error) {
    case SSL_ERROR_WANT_READ:
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_WANT_WRITE:
        event.events = EPOLLOUT;
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


void Proxy::shakedhand() {
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN |EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    
    handleEvent=(void (Con::*)(uint32_t))&Host::defaultHE;
}



int select_next_proto_cb(SSL* ssl,
                         unsigned char **out, unsigned char *outlen,
                         const unsigned char *in, unsigned int inlen,
                         void *arg)
{
    (void)ssl;
    *out=(unsigned char*)"spdy/3.1";
    *outlen=strlen((char*)*out);

    return SSL_TLSEXT_ERR_OK;
}


void Proxy::waitconnectHE(uint32_t events) {
    if( guest == NULL) {
        clean();
        return;
    }
    if (events & EPOLLOUT) {
        int error;
        socklen_t len=sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            perror("proxy getsokopt");
            clean();
            return;
        }

        if (error != 0) {
            LOGE( "connect to proxy:%s\n", strerror(error));
            if(connect()<0) {
                clean();
            }
            return;
        }
        ctx = SSL_CTX_new(SSLv23_client_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            clean();
            return;
        }
        SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3); //去除支持SSLv2 SSLv3
        SSL_CTX_set_next_proto_select_cb(ctx,select_next_proto_cb,NULL);

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        
        handleEvent=(void (Con::*)(uint32_t))&Proxy::shakehandHE;
    }
}


void Proxy::shakehandHE(uint32_t events) {
    if ((events & EPOLLIN) || (events & EPOLLOUT)) {
        int ret = SSL_connect(ssl);
        if (ret != 1) {
            if(showerrinfo(ret,"ssl connect error")){
                clean();
            }
        }else{
            shakedhand();
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("proxy unkown error: %s\n",strerror(errno));
        clean();
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
