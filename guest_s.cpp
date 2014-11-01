#include <errno.h>
#include <sys/epoll.h>
#include <openssl/err.h>

#include "net.h"
#include "guest_s.h"
#include "host.h"
#include "parse.h"



Guest_s::Guest_s(int fd, int efd, SSL* ssl): Guest(fd, efd), ssl(ssl) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    
    handleEvent=(void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}

Guest_s::~Guest_s() {
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int Guest_s::Read(char* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


int Guest_s::Write() {
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

void Guest_s::shakedhand() {
    const unsigned char *data;
    unsigned int len;
    SSL_get0_next_proto_negotiated(ssl,&data,&len);
    if(data) {
        if(strncasecmp((const char*)data,"spdy/3.1",len)==0) {
            protocol=spdy3_1;
        } else {
            LOGE( "([%s]:%d): unknown protocol:%.*s\n",sourceip, sourceport,len,data);
            clean();
            return;
        }
    }
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    
    handleEvent=(void (Con::*)(uint32_t))&Guest::getheaderHE;
}

int Guest_s::showerrinfo(int ret, const char* s) {
    epoll_event event;
    event.data.ptr = this;
    int error = SSL_get_error(ssl, ret);
    switch(error) {
    case SSL_ERROR_WANT_READ:
        event.events = EPOLLIN ;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_WANT_WRITE:
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_ZERO_RETURN:
        break;
    case SSL_ERROR_SYSCALL:
        LOGE( "([%s]:%d): %s:%s\n",
              sourceip, sourceport,s, strerror(errno));
        break;
    default:
        LOGE( "([%s]:%d): %s:%s\n",
              sourceip, sourceport,s, ERR_error_string(error, NULL));
    }
    return 1;
}



void Guest_s::shakehandHE(uint32_t events) {
    if ((events & EPOLLIN)|| (events & EPOLLOUT)) {
        int ret = SSL_accept(ssl);
        if (ret != 1) {
            if(showerrinfo(ret,"ssl accept error")){
                clean();
            }
        }else{
            shakedhand();
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE( "([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean();
    }
}

