#include "guest_sni.h"
#include "prot/tls.h"
#include "misc/util.h"
#include "misc/net.h"

#include <string.h>
#include <stdlib.h>

Guest_sni::Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx):Guest(fd, addr, ctx){
    Http_Proc = &Guest_sni::AlwaysProc;
    rwer->SetReadCB([this](size_t len){
        char *hostname = nullptr;
        const char *buffer = rwer->rdata();
        int ret = parse_tls_header(buffer, len, &hostname);
        if(ret > 0){
            char buff[HEADLENLIMIT];
            int len = sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
            HttpReqHeader* req = new HttpReqHeader(buff, len);
            ReqProc(req);
            rwer->SetReadCB(std::bind(&Guest_sni::ReadHE, this, _1));
        }else if(ret != -1){
            deleteLater(SNI_HOST_ERR);
        }
        free(hostname);
    });
}

void Guest_sni::response(void*, HttpRes*){
}
