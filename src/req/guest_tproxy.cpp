#include "guest_tproxy.h"
#include "guest_sni.h"
#include "res/responser.h"
#include "misc/config.h"
#include "prot/memio.h"

#include <inttypes.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>


static int getDstAddr(int fd, int family, sockaddr_storage* dst) {
    socklen_t socklen = sizeof(*dst);
    if(family == AF_INET) {
        if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &socklen)) {
            LOGE("failed to get original dst: %s\n", strerror(errno));
            return -1;
        }
    }else if(family == AF_INET6) {
        if(getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, dst, &socklen)) {
            LOGE("failed to get original dst: %s\n", strerror(errno));
            return -1;
        }
    }else {
        LOGE("unknown family: %d\n", family);
        return -1;
    }
    return 0;
}


Guest_tproxy::Guest_tproxy(int fd, const sockaddr_storage* src): Guest(fd, src, nullptr) {
    sockaddr_storage dst;
    if(getDstAddr(fd, src->ss_family, &dst)) {
        LOGF("failed to get src addr for tproxy\n");
    }

    headless = true;
    Http_Proc = &Guest_tproxy::AlwaysProc;
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF CRLF, storage_ntoa(&dst));
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    if(header == nullptr) {
        LOGE("Guest_tproxy: UnpackHttpReq failed\n");
        return;
    }
    header->set("User-Agent", "tproxy");
    ReqProc(0, header);
}

Guest_tproxy::Guest_tproxy(int fd, const sockaddr_storage* src, Buffer&& bb): Guest(fd, src, nullptr) {
    sockaddr_storage dst;
    if(getDstAddr(fd, src->ss_family, &dst)) {
        LOGF("failed to get src addr for tproxy\n");
    }

    headless = true;
    Http_Proc = &Guest_tproxy::AlwaysProc;
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: udp" CRLF CRLF, storage_ntoa(&dst));
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    if(header == nullptr) {
        LOGE("Guest_tproxy: UnpackHttpReq failed\n");
        return;
    }
    header->set("User-Agent", "tproxy");
    ReqProc(0, header);
    DataProc(bb);
}
