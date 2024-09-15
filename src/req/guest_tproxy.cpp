#include "guest_tproxy.h"
#include "guest_sni.h"
#include "res/responser.h"
#include "res/fdns.h"
#include "misc/config.h"
#include "misc/util.h"
#include "prot/netio.h"

#include <inttypes.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

struct pinfo{
    pid_t pid;
    char comm[16];
}__attribute__((packed));

static int getDstAddr(int fd, int family, sockaddr_storage* dst) {
    socklen_t socklen = sizeof(*dst);
    if(family == AF_INET) {
        if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &socklen)) {
            LOGE("failed to get original dst: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    if(family == AF_INET6) {
        if(getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, dst, &socklen)) {
            LOGE("failed to get original dst: %s\n", strerror(errno));
            return -1;
        }
        sockaddr_in6* addr6 = (sockaddr_in6*)dst;
        struct in_addr ip4 = getMapped(addr6->sin6_addr, IPV4MAPIPV6);
        if(ip4.s_addr != INADDR_NONE){
            sockaddr_in* addr = (sockaddr_in*)dst;
            addr->sin_family = AF_INET;
            addr->sin_addr = ip4;
        }
        return 0;
    }
    LOGE("unknown family: %d\n", family);
    return -1;
}

Guest_tproxy::Guest_tproxy(int fd, const sockaddr_storage* src):
    Guest(std::make_shared<StreamRWer>(fd, src, [](int, int){}))
{
    sockaddr_storage dst;
    if(getDstAddr(fd, src->ss_family, &dst)) {
        LOGE("(%s) failed to get src addr for tproxy\n", storage_ntoa(src));
        deleteLater(TPROXY_HOST_ERR);
        return;
    }

    headless = true;
    Http_Proc = &Guest_tproxy::AlwaysProc;
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF CRLF, storage_ntoa(&dst));
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    if(header == nullptr) {
        LOGE("(%s) Guest_tproxy: UnpackHttpReq failed\n", storage_ntoa(src));
        deleteLater(TPROXY_HOST_ERR);
        return;
    }
    struct pinfo pinfo;
    socklen_t plen = sizeof(pinfo);
    if(getsockopt(fd, SOL_IP, 0xff, &pinfo, &plen)) {
        header->set("User-Agent", generateUA(opt.ua, "", 0));
    } else {
        header->set("User-Agent", generateUA(opt.ua, std::string(pinfo.comm) + "/" + std::to_string(pinfo.pid), 0));
    }
    ReqProc(0, header);
}

Guest_tproxy::Guest_tproxy(int fd, const sockaddr_storage* src, Buffer&& bb):
    Guest(std::make_shared<PacketRWer>(fd, src, [](int, int){}))
{
    static uint64_t  dnsid = 1;
    sockaddr_storage dst;
    if(getDstAddr(fd, src->ss_family, &dst)) {
        LOGE("(%s) failed to get src addr for tproxy\n", storage_ntoa(src));
        deleteLater(TPROXY_HOST_ERR);
        return;
    }
    if(((sockaddr_in*)&dst)->sin_port == htons(DNSPORT)){
        bb.id = dnsid++;
        FDns::GetInstance()->query(std::move(bb), rwer);
        rwer = nullptr;
        deleteLater(NOERROR);
        return;
    }

    headless = true;
    Http_Proc = &Guest_tproxy::AlwaysProc;
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: udp" CRLF CRLF, storage_ntoa(&dst));
    std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, slen);
    if(header == nullptr) {
        LOGE("(%s) Guest_tproxy: UnpackHttpReq failed\n", storage_ntoa(src));
        deleteLater(TPROXY_HOST_ERR);
        return;
    }
    struct pinfo pinfo;
    socklen_t plen = sizeof(pinfo);
    if(getsockopt(fd, SOL_IP, 0xff, &pinfo, &plen)) {
        header->set("User-Agent", generateUA(opt.ua, "", 0));
    } else {
        header->set("User-Agent", generateUA(opt.ua, std::string(pinfo.comm) + "/" + std::to_string(pinfo.pid), 0));
    }
    ReqProc(0, header);
    DataProc(bb);
}
