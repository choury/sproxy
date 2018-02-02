#include "guest_sni.h"
#include "misc/tls.h"
#include "misc/util.h"
#include "misc/net.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

Guest_sni::Guest_sni(int fd, const sockaddr_un *myaddr):Guest(fd, myaddr){
    Http_Proc = &Guest_sni::AlwaysProc;
}

void Guest_sni::initHE(uint32_t events) {
    char *hostname = nullptr;
    const char *buffer = rwer->data();
    int ret = parse_tls_header(buffer, rwer->rlength(), &hostname);
    if(ret > 0){
        char buff[HEADLENLIMIT];
        int len = sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
        HttpReqHeader* req = new HttpReqHeader(buff, len, this);
        assert(responser_ptr == nullptr);
        ReqProc(req);
        if(responser_ptr == nullptr){
            deleteLater(PEER_LOST_ERR);
        }else{
            //TODO:
            assert(0);
        }
    }else if(ret != -1){
        deleteLater(SNI_HOST_ERR);
    }
    free(hostname);
}

void Guest_sni::response(HttpResHeader* res){
    assert((long)res->index == 1);
    delete res;
}

const char* Guest_sni::getsrc(const void *){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d [SNI]", sourceip, sourceport);
    return src;
}
