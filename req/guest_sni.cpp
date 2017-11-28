#include "guest_sni.h"
#include "res/host.h"
#include "misc/tls.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

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
            if(error){
                LOGE("(%s): guest_sni error:%s\n", getsrc(nullptr), strerror(error));
            }
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if(events & EPOLLIN){
        int ret=read(fd, http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if(ret <= 0 && showerrinfo(ret, "guest_sni read error")) {
            deleteLater(READ_ERR);
            return;
        }
        http_getlen += ret;
        char *hostname = nullptr;
        ret = parse_tls_header(http_buff, http_getlen, &hostname);
        if(ret > 0){
            char buff[HEADLENLIMIT];
            sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
            HttpReqHeader* req = new HttpReqHeader(buff, this);
            assert(responser_ptr == nullptr);
            ReqProc(req);
            if(responser_ptr == nullptr){
                deleteLater(PEER_LOST_ERR);
            }else{
                updateEpoll(EPOLLIN | EPOLLOUT);
                handleEvent = (void (Con::*)(uint32_t))&Guest_sni::defaultHE;
            }
        }else if(ret != -1){
            deleteLater(INTERNAL_ERR);
        }
        free(hostname);
    }
    
    if(events & EPOLLOUT){
        updateEpoll(EPOLLIN);
    }
}

void Guest_sni::response(HttpResHeader* res){
    assert((long)res->index == 1);
    (this->*Http_Proc)();
    delete res;
}

const char* Guest_sni::getsrc(void *){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d [SNI]", sourceip, sourceport);
    return src;
}
