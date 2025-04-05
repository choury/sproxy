#include "guest_tproxy.h"
#include "res/fdns.h"
#include "misc/config.h"
#include "misc/util.h"
#include "prot/netio.h"

#include <inttypes.h>

#include <linux/netfilter_ipv4.h>
//#include <linux/netfilter_ipv6/ip6_tables.h>
// pointer to void BUG in ip6_tables.h on ubuntu 20.04
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST            80
#endif



/* Example for iptable tproxy, for --tproxy 3333 and ipv4 only:
 *
 * iptables -t mangle -A PREROUTING -m addrtype --dst-type LOCAL -j RETURN
 * iptables -t mangle -A PREROUTING -p udp -j TPROXY --on-port 3333  --tproxy-mark 3333/3333
 * iptables -t mangle -A PREROUTING -p tcp -j TPROXY --on-port 3333  --tproxy-mark 3333/3333
 * ip rule add fwmark 3333 lookup 3333
 * ip route add local 0.0.0.0/0 dev lo table 3333
 */

struct pinfo{
    pid_t pid;
    char comm[16];
}__attribute__((packed));

static int getDstAddr_bpf(int fd, int family, sockaddr_storage* dst) {
    socklen_t socklen = sizeof(*dst);
    if(family == AF_INET) {
        if(getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, dst, &socklen)) {
            LOGE("failed to get original dst: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
    if(family == AF_INET6) {
        if(getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, dst, &socklen)) {
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

static int getDstAddr_tcp(int fd, int family, sockaddr_storage* dst) {
    if(opt.bpf_cgroup) {
        return getDstAddr_bpf(fd, family, dst);
    } else {
        socklen_t socklen = sizeof(*dst);
        if(getsockname(fd, (sockaddr*)dst, &socklen)) {
            LOGE("failed to get socket dst: %s\n", strerror(errno));
            return -1;
        }
        return 0;
    }
}

//tcp
Guest_tproxy::Guest_tproxy(int fd, sockaddr_storage* src):
    Guest(std::make_shared<StreamRWer>(fd, src, [](int, int){}))
{
    sockaddr_storage dst;
    if(getDstAddr_tcp(fd, src->ss_family, &dst)) {
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

static int getDstAddr_udp(int fd, int family, sockaddr_storage* dst) {
    if(opt.bpf_cgroup) {
        return getDstAddr_bpf(fd, family, dst);
    } else {
        if(((sockaddr_in*)dst)->sin_port == 0){
            LOGE("failed to get socket dst [%s]: zero port\n", storage_ntoa(dst));
            return -1;
        }
        return 0;
    }
}


//udp
Guest_tproxy::Guest_tproxy(int fd, sockaddr_storage* src, sockaddr_storage* dst, Buffer&& bb):
    Guest(std::make_shared<PacketRWer>(fd, src, [](int, int){}))
{
    if(getDstAddr_udp(fd, src->ss_family, dst)) {
        LOGE("(%s) failed to get src addr for tproxy\n", storage_ntoa(src));
        deleteLater(TPROXY_HOST_ERR);
        return;
    }
    if(((sockaddr_in*)dst)->sin_port == htons(DNSPORT)){
        bb.id = nextId();
        FDns::GetInstance()->query(std::move(bb), rwer);
        rwer = nullptr;
        deleteLater(NOERROR);
        return;
    }

    headless = true;
    Http_Proc = &Guest_tproxy::AlwaysProc;
    char buff[HEADLENLIMIT];
    int slen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: udp" CRLF CRLF, storage_ntoa(dst));
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
