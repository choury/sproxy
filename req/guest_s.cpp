#include "guest_s.h"
#include "guest_s2.h"

//#include <unistd.h>
//#include <openssl/err.h>


Guest_s::Guest_s(int fd, struct sockaddr_in6 *myaddr, Ssl* ssl): Guest(fd, myaddr), ssl(ssl){
    accept_start_time = time(nullptr);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}


Guest_s::~Guest_s() {
    if(ssl){
        delete ssl;
    }
}

void Guest_s::discard(){
    ssl = nullptr;
    Guest::discard();
}

ssize_t Guest_s::Read(void* buff, size_t size) {
    return ssl->read(buff, size);
}

ssize_t Guest_s::Write(const void *buff, size_t size) {
    return ssl->write(buff, size);
}


void Guest_s::shakehandHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest_s error:%s\n", getsrc(nullptr), strerror(error));
        }
        clean(INTERNAL_ERR, 0);
        return;
    }

    if ((events & EPOLLIN)|| (events & EPOLLOUT)) {
        int ret = ssl->accept();
        if (ret != 1) {
            if (time(nullptr) - accept_start_time>=120 || showerrinfo(ret, "ssl accept error")) {
                clean(SSL_SHAKEHAND_ERR, 0);
            }
        } else {
            updateEpoll(EPOLLIN);
            handleEvent = (void (Con::*)(uint32_t))&Guest_s::defaultHE;

            const unsigned char *data;
            unsigned int len;
            ssl->get_alpn(&data, &len);
            if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
                new Guest_s2(fd, sourceip, sourceport, ssl);
                this->discard();
                clean(NOERROR, 0);
                return;
            }
        }
    } 
}

