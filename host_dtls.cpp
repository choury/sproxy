#include "host_dtls.h"
#include <openssl/err.h>

extern std::map<Host*,time_t> connectmap;

Host_dtls::Host_dtls(const char* hostname, uint16_t port):Host(hostname, port){
    ctx = SSL_CTX_new(DTLS_client_method());
    ssl = SSL_new(ctx);
}

ssize_t Host_dtls::Read(void* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


ssize_t Host_dtls::Write(const void *buff, size_t size) {
    return SSL_write(ssl, buff, size);
}

int Host_dtls::connect() {
    connectmap[this]=time(NULL);
    if (testedaddr>= addrs.size()) {
        return -1;
    } else {
        if (fd > 0) {
            updateEpoll(0);
            close(fd);
        }
        if (testedaddr != 0) {
            RcdDown(hostname, addrs[testedaddr-1]);
        }
        fd = Connect(&addrs[testedaddr++], SOCK_DGRAM);
        if (fd < 0) {
            LOGE("connect to %s failed\n", this->hostname);
            return connect();
        }

        BIO* bio = BIO_new_dgram(fd, BIO_CLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &addrs[testedaddr-1]);
        SSL_set_bio(ssl, bio, bio);
        updateEpoll(EPOLLOUT);
        handleEvent = (void (Con::*)(uint32_t))&Host_dtls::shakehandHE;
        return 0;
    }
}


void Host_dtls::shakehandHE(uint32_t events) {
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
        handleEvent = (void (Con::*)(uint32_t))&Host_dtls::defaultHE;

        const unsigned char *data;
        unsigned int len;
        SSL_get0_alpn_selected(ssl, &data, &len);
        if (data && strncasecmp((const char*)data, "h2", len) == 0) {
            LOGE("get h2\n");
        }
        connectmap.erase(this);
        return;

    }
}

int Host_dtls::showerrinfo(int ret, const char* s) {
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
