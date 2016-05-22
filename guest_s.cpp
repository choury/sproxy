#include "guest_s2.h"
#include "host.h"
#include "file.h"
#include "cgi.h"

#include <unistd.h>
#include <openssl/err.h>

Guest_s::Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL* ssl): Guest(fd, myaddr), ssl(ssl) {
    accept_start_time = time(nullptr);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}

Guest_s::Guest_s(Guest_s *const copy): Guest(copy), ssl(copy->ssl) {
    copy->fd = 0;
    copy->ssl = nullptr;
    copy->reset_this_ptr(this);
	copy->clean(NOERROR, nullptr);
}


Guest_s::~Guest_s() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

ssize_t Guest_s::Read(void* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}

ssize_t Guest_s::Write(const void *buff, size_t size) {
    return SSL_write(ssl, buff, size);
}


int Guest_s::showerrinfo(int ret, const char* s) {
    if(ret<=0) {
        int error = SSL_get_error(ssl, ret);
        switch (error) {
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_WANT_WRITE:
            updateEpoll(EPOLLIN | EPOLLOUT);
            return 0;
        case SSL_ERROR_ZERO_RETURN:
            break;
        case SSL_ERROR_SYSCALL:
            error = ERR_get_error();
            if (error == 0 && ret == 0){
                LOGE("([%s]:%d): %s: the connection was lost\n",
                     sourceip, sourceport, s);
            }else if (error == 0 && ret == -1){
                LOGE("([%s]:%d): %s:%s\n",
                     sourceip, sourceport, s, strerror(errno));
            }else{
                LOGE("([%s]:%d): %s:%s\n",
                     sourceip, sourceport, s, ERR_error_string(error, NULL));
            }
            break;
        default:
            LOGE("([%s]:%d): %s:%s\n",
                sourceip, sourceport, s, ERR_error_string(ERR_get_error(), NULL));
        }
    }else{
         LOGE("([%s]:%d): %s:%d\n", sourceip, sourceport, s, ret);
    }
    ERR_clear_error();
    return 1;
}



void Guest_s::shakehandHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(INTERNAL_ERR, this);
    }
    
    if ((events & EPOLLIN)|| (events & EPOLLOUT)) {
        int ret = SSL_accept(ssl);
        if (ret != 1) {
            if (time(nullptr) - accept_start_time>=120 || showerrinfo(ret, "ssl accept error")) {
                clean(SSL_SHAKEHAND_ERR, this);
            }
        } else {
            updateEpoll(EPOLLIN);
            handleEvent = (void (Con::*)(uint32_t))&Guest_s::defaultHE;

            const unsigned char *data;
            unsigned int len;
            SSL_get0_alpn_selected(ssl, &data, &len);
            if (data && strncasecmp((const char*)data, "h2", len) == 0) {
                new Guest_s2(this);
                delete this;
                return;
            }
        }
    } 
}

