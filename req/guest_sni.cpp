#include "guest_sni.h"
#include "misc/tls.h"
#include "misc/util.h"
#include "misc/net.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

Guest_sni::Guest_sni(int fd, const sockaddr_un *myaddr):Guest(fd, myaddr){
    Http_Proc = &Guest_sni::AlwaysProc;
    rwer->SetReadCB([this](size_t len){
        char *hostname = nullptr;
        const char *buffer = rwer->data();
        int ret = parse_tls_header(buffer, len, &hostname);
        if(ret > 0){
            char buff[HEADLENLIMIT];
            int len = sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
            HttpReqHeader* req = new HttpReqHeader(buff, len, this);
            assert(responser_ptr == nullptr);
            ReqProc(req);
            if(responser_ptr == nullptr){
                deleteLater(PEER_LOST_ERR);
            }else{
                rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1));
            }
        }else if(ret != -1){
            deleteLater(SNI_HOST_ERR);
        }
        free(hostname);
    });
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
