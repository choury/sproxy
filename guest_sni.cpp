#include "guest_sni.h"
#include "host.h"
#include "tls.h"

Guest_sni::Guest_sni(int fd, sockaddr_in6 *myaddr):Guest(fd, myaddr){
    Http_Proc = &Guest_sni::AlwaysProc;
    handleEvent = (void (Con::*)(uint32_t))&Guest_sni::initHE;
}

void Guest_sni::initHE(uint32_t events) {
    if(events & EPOLLIN){
        int ret=read(fd, http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if(ret <= 0){
            if (showerrinfo(ret, "guest_sni read error")) {
                clean(this, READ_ERR);
            }
            return;
        }
        http_getlen += ret;
        char *hostname;
        ret = parse_tls_header(http_buff, http_getlen, &hostname);
        if(ret > 0){
            if (checkproxy(hostname)) {
                LOG("([%s]%d): Sni(proxy):%s\n", sourceip, sourceport, hostname);
            }else{
                LOG("([%s]%d): Sni:%s\n", sourceip, sourceport, hostname);
            }
            char buff[HEADLENLIMIT];
            sprintf(buff, "CONNECT %s:%d" CRLF CRLF, hostname, 443);
            HttpReqHeader req(buff);
            Host::gethost(req, this);
            handleEvent = (void (Con::*)(uint32_t))&Guest_sni::defaultHE;
        }else if(ret != -1){
            clean(this, INTERNAL_ERR);
        }
    }
}

void Guest_sni::Response(Peer *who, HttpResHeader &res){
}
