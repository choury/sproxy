#include "guest_sni.h"
#include "host.h"
#include "tls.h"

Guest_sni::Guest_sni(int fd, sockaddr_in6 *myaddr):Guest(fd, myaddr){
    Http_Proc = &Guest_sni::AlwaysProc;
    updateEpoll(EPOLLIN);
    handleEvent = (void (Con::*)(uint32_t))&Guest_sni::initHE;
}

void Guest_sni::initHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_sni error:%s\n",
                 sourceip, sourceport, strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }

    if(events & EPOLLIN){
        int ret=read(fd, http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if(ret <= 0){
            if (showerrinfo(ret, "guest_sni read error")) {
                clean(READ_ERR, this);
            }
            return;
        }
        http_getlen += ret;
        char *hostname = nullptr;
        ret = parse_tls_header(http_buff, http_getlen, &hostname);
        if(ret > 0){
            char buff[HEADLENLIMIT];
            sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
            HttpReqHeader req(buff, this);
            responser_ptr = distribute(req, responser_ptr);
            updateEpoll(EPOLLIN | EPOLLOUT);
            handleEvent = (void (Con::*)(uint32_t))&Guest_sni::defaultHE;
        }else if(ret != -1){
            clean(INTERNAL_ERR, this);
        }
        free(hostname);
    }
    if(events & EPOLLOUT){
        updateEpoll(EPOLLIN);
    }
}

void Guest_sni::response(HttpResHeader &){
}

const char* Guest_sni::getsrc(){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d [SNI]", sourceip, sourceport);
    return src;
}
