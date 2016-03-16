#include "guest_s2.h"
#include "host.h"
#include "file.h"
#include "cgi.h"

#include <unistd.h>
#include <bits/local_lim.h>
#include <netinet/tcp.h>
#include <openssl/err.h>

Guest_s::Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL* ssl): Guest(fd, myaddr), ssl(ssl) {
    accept_start_time = time(nullptr);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}

Guest_s::Guest_s(sockaddr_in6* myaddr, SSL* ssl): Guest(0, myaddr), ssl(ssl) {
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    Bind_any(fd, 4433);
    if(connect(fd, (struct sockaddr*)myaddr, sizeof(struct sockaddr_in6))){
        LOGE("([%s]:%d): connect error: %s\n", sourceip, sourceport, strerror(errno));
    }
    /* Set new fd and set BIO to connected */
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, myaddr);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::shakehandHE;


}


Guest_s::Guest_s(Guest_s *const copy): Guest(copy), ssl(copy->ssl) {
    copy->fd = 0;
    copy->ssl = nullptr;
	copy->clean(NOERROR, queryconnect(copy));
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

void Guest_s::shakedhand() {
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s::defaultHE;

    const unsigned char *data;
    unsigned int len;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (data) {
        if (strncasecmp((const char*)data, "h2", len) == 0) {
            new Guest_s2(this);
            delete this;
            return;
        }
    }
}


int Guest_s::showerrinfo(int ret, const char* s) {
    if(ret<=0) {
        epoll_event event;
        event.data.ptr = this;
        int error = SSL_get_error(ssl, ret);
        switch (error) {
        case SSL_ERROR_WANT_READ:
            return 0;
        case SSL_ERROR_WANT_WRITE:
            event.events = EPOLLIN|EPOLLOUT;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
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
            shakedhand();
        }
    } 
}

void Guest_s::ReqProc(HttpReqHeader& req) {
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    LOG("([%s]:%d): %s %s\n", sourceip, sourceport, req.method, req.url);
    
    flag = 0;
    if(req.ismethod("SHOW")){
        writelen += ::showstatus(wbuff+writelen, req.url);
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return; 
    } else if(req.ismethod("FLUSH")){
        if(strcasecmp(req.url, "dns") == 0){
            flushdns();
            Write(H200, strlen(H200));
            return;
        }
        if(strcasecmp(req.url, "cgi") == 0){
            flushcgi();
            Write(H200, strlen(H200));
            return;
        }
        return;
    }
        
    if (req.url[0] == '/' && strcasecmp(hostname, req.hostname)) {
        req.getfile();
        if (endwith(req.filename,".so")) {
            Cgi::getcgi(req, this);
        } else {
            File::getfile(req,this);
        }
    } else {
        Host::gethost(req, this);
    }
}
