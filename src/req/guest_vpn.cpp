#include "guest_vpn.h"
#include "res/fdns.h"
#include "prot/tcpip/tunio.h"
#include "misc/config.h"
#include "misc/util.h"

#include <fstream>
#include <assert.h>
#include <inttypes.h>

extern "C" void vpn_stop();
Guest_vpn::Guest_vpn(int fd): Requester(nullptr) {
    init(std::make_shared<TunRWer>(fd,
        std::bind(&Guest_vpn::ReqProc, this, _1, _2),
        [](int ret, int code){
            LOGE("vpn_server error: %d/%d\n", ret, code);
            vpn_stop();
        }
    ));
    rwer->SetReadCB([this](uint64_t id, const void* data, size_t len) -> size_t {
        if(statusmap.count(id) == 0){
            return 0;
        }
        auto& status = statusmap[id];
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);

        if(len == 0) {
            status.req->send(nullptr);
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                rwer->addjob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
            }
        } else if(status.req->cap() < (int)len){
            LOGE("[%" PRIu32 "]: <guest_vpn> the host's buff is full, drop packet (%s)\n",
                 status.req->header->request_id, status.req->header->geturl().c_str());
            return len;
        }else{
            status.req->send(data, len);
        }
        return 0;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        auto& status = statusmap[id];
        if(status.res == nullptr){
            return;
        }
        if((status.flags & HTTP_RES_COMPLETED) == 0){
            status.res->more();
        }
    });
    std::dynamic_pointer_cast<TunRWer>(rwer)->setResetHandler([this](uint64_t id, uint32_t){
        if(statusmap.count(id)) {
            Clean(id, statusmap[id]);
        }
    });
}

Guest_vpn::~Guest_vpn(){
    statusmap.clear();
}

#if __linux__
#include <fstream>
static const char* getProg(std::shared_ptr<const Ip> pac) {
    auto src_ = pac->getsrc();
    auto dst_ = pac->getdst();
    if(!startwith(getRdns(src_).c_str(), "VPN")) {
        return "NOT-LOCAL";
    }
#if __ANDROID__
    if(android_get_device_api_level() >= 29){
        return getPackageNameFromAddr(pac->gettype(), &src_, &dst_);
    }
#endif
    if(pac->getsrc().ss_family == AF_INET){
        std::ifstream netfile;
        switch(pac->gettype()){
        case IPPROTO_TCP:
            netfile.open("/proc/net/tcp");
            break;
        case IPPROTO_UDP:
            netfile.open("/proc/net/udp");
            break;
        case IPPROTO_ICMP:
            netfile.open("/proc/net/icmp");
            break;
        default:
            return "<NONE>";
        }

        sockaddr_in* src = (sockaddr_in*)&src_;
        sockaddr_in* dst = (sockaddr_in*)&dst_;
        if(netfile.good()) {
            std::string line;
            std::getline(netfile, line); //drop the title line
            while (std::getline(netfile, line)) {
                uint32_t srcip, dstip;
                unsigned int srcport, dstport;
                int uid = 0;
                ino_t inode = 0;
                sscanf(line.c_str(), "%*d: %x:%x %x:%x %*x %*x:%*x %*d:%*x %*d %d %*d %lu",
                                    &srcip, &srcport, &dstip, &dstport, &uid, &inode);
                if(src->sin_port != htons(srcport) || src->sin_addr.s_addr != srcip){
                    continue;
                }
                // for udp and icmp, it usually no been bind
                if((pac->gettype() != IPPROTO_TCP) ||
                    (dst->sin_addr.s_addr == dstip && dst->sin_port == htons(dstport)))
                {
#if __ANDROID__
                    return getPackageNameFromUid(uid);
#else
                    return findprogram(inode);
#endif
                }
            }

            netfile.clear();
            netfile.seekg(0);
        }
        LOGD(DVPN, "Get src failed for %d %08X:%04X %08X:%04X\n",
                        pac->gettype(),
                        src->sin_addr.s_addr, ntohs(src->sin_port),
                        dst->sin_addr.s_addr, ntohs(dst->sin_port));
    }
    std::ifstream net6file;
    switch(pac->gettype()){
    case IPPROTO_TCP:
        net6file.open("/proc/net/tcp6");
        break;
    case IPPROTO_UDP:
        net6file.open("/proc/net/udp6");
        break;
    case IPPROTO_ICMPV6:
        net6file.open("/proc/net/icmp6");
        break;
    default:
        return "<NONE>";
    }
    sockaddr_in6* src = (sockaddr_in6*)&src_;
    sockaddr_in6* dst = (sockaddr_in6*)&dst_;
    in6_addr mysrcip, mydstip;
    if(pac->getsrc().ss_family == AF_INET){
        memcpy(mysrcip.s6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
        memcpy(mydstip.s6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
        mysrcip.s6_addr32[3] = ((sockaddr_in*)&src)->sin_addr.s_addr;
        mydstip.s6_addr32[3] = ((sockaddr_in*)&dst)->sin_addr.s_addr;
    }else{
        mysrcip = src->sin6_addr;
        mydstip = dst->sin6_addr;
    }
    if(net6file.good()) {
        std::string line;
        std::getline(net6file, line); //drop the title line
        while (std::getline(net6file, line)) {
            unsigned int srcport, dstport;
            int uid = 0;
            ino_t inode = 0;
            uint32_t srcip[4], dstip[4];
            sscanf(line.c_str(), "%*d: %8X%8X%8X%8X:%X %8X%8X%8X%8X:%X %*x %*x:%*x %*d:%*x %*d %d %*d %lu",
                                srcip, srcip+1, srcip+2, srcip+3, &srcport,
                                dstip, dstip+1, dstip+2, dstip+3, &dstport, &uid, &inode);

            if(src->sin6_port != htons(srcport)){
                continue;
            }
            if((pac->gettype() != IPPROTO_TCP) ||
                (memcmp(&mydstip, dstip, sizeof(dstip)) == 0 && dst->sin6_port == htons(dstport)))
            {
#if __ANDROID__
                return getPackageNameFromUid(uid);
#else
                return findprogram(inode);
#endif
            }
        }
        net6file.clear();
        net6file.seekg(0);
    }
    LOGD(DVPN, "Get src failed for %d %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X\n",
                    pac->gettype(),
                    mysrcip.s6_addr32[0], mysrcip.s6_addr32[1], mysrcip.s6_addr32[2], mysrcip.s6_addr32[3],
                    ntohs(src->sin6_port),
                    mydstip.s6_addr32[0], mydstip.s6_addr32[1], mydstip.s6_addr32[2], mydstip.s6_addr32[3],
                    ntohs(dst->sin6_port));
    return "<Unknown-inode>";
}
#endif

static const char* generateUA(std::shared_ptr<const Ip> pac, uint32_t request_id) {
    static char UA[URLLIMIT];
    if(opt.ua){
        sprintf(UA, "%s Sproxy/%s VPN/%u",
                opt.ua, getVersion(), request_id);
        return UA;
    }
#ifdef __ANDROID__
    sprintf(UA, "Sproxy/%s (Build %s) (%s) VPN/%u %s App/%s",
            getVersion(),
            getBuildTime(),
            getDeviceName(),
            request_id,
            getProg(pac),
            appVersion);
#elif __linux__
    sprintf(UA, "Sproxy/%s (Build %s) (%s) VPN/%u %s",
            getVersion(),
            getBuildTime(),
            getDeviceInfo(),
            request_id,
            getProg(pac));
#else
    sprintf(UA, "Sproxy/%s (Build %s) (%s) VPN/%u",
            getVersion(),
            getBuildTime(),
            getDeviceInfo(),
            request_id);
#endif
    return UA;
}


void Guest_vpn::response(void* index, std::shared_ptr<HttpRes> res) {
    uint64_t id = (uint64_t)index;
    auto& status = statusmap.at(id);
    assert(status.res == nullptr);
    status.res = res;
    res->attach([this, id](ChannelMessage& msg) -> int{
        auto& status = statusmap.at(id);
        std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:{
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            LOGD(DVPN, "<guest_vpn> get response [%" PRIu64"]: %s\n", id, header->status);
            if((status.flags & VPN_DNSREQ_F) == 0){
                auto src = status.pac->getsrc();
                HttpLog(storage_ntoa(&src), status.req->header, header);
            }
            if(memcmp(header->status, "200", 3) == 0){
                trwer->sendMsg(id, TUN_MSG_SYN);
                return 1;
            }else if(header->status[0] == '4'){
                trwer->sendMsg(id, TUN_MSG_BLOCK);
            }else if(header->status[0] == '5'){
                trwer->sendMsg(id, TUN_MSG_UNREACH);
            }else{
                LOGE("unknown response\n");
            }
            status.res->detach();
            rwer->addjob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
            return 0;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            msg.data.id = id;
            if (msg.data.len == 0) {
                LOGD(DVPN, "<guest_vpn> %" PRIu32 " recv data [%" PRIu64"]: EOF\n",
                     status.req->header->request_id, id);
                rwer->buffer_insert({nullptr, id});
                status.flags |= HTTP_RES_COMPLETED;
                if(status.flags & HTTP_REQ_COMPLETED) {
                    rwer->addjob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
                }
            }else{
                LOGD(DVPN, "<guest_vpn> %" PRIu32 " recv data [%" PRIu64"]: %zu\n",
                     status.req->header->request_id, id, msg.data.len);
                rwer->buffer_insert(std::move(msg.data));
            }
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            handle(id, msg.signal);
            return 0;
        }
        return 0;
    }, [this, id]{ return rwer->cap(id);});
}

void Guest_vpn::ReqProc(uint64_t id, std::shared_ptr<const Ip> pac) {
    assert(statusmap.count(id) == 0);
    statusmap.emplace(id, VpnStatus{});
    auto& status = statusmap[id];
    status.pac = pac;
    char buff[HEADLENLIMIT];
    switch(pac->gettype()){
    case IPPROTO_TCP:{
        //create a http proxy request
        int headlen = sprintf(buff, "CONNECT %s" CRLF CRLF,
                              getRdns(pac->getdst()).c_str());

        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(pac, header->request_id));
        status.req = std::make_shared<HttpReq>(header, 
                        std::bind(&Guest_vpn::response, this, (void*)id, _1), 
                        [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    case IPPROTO_UDP:{
        //create a http proxy request
        int headlen = sprintf(buff, "SEND %s" CRLF CRLF,
                              getRdns(pac->getdst()).c_str());

        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(pac, header->request_id));
        status.req = std::make_shared<HttpReq>(header, 
                        std::bind(&Guest_vpn::response, this, (void*)id, _1), 
                        [this, id]{rwer->Unblock(id);});
        if(pac->udp->getdport() == 53){
            status.flags |= VPN_DNSREQ_F;
            FDns::GetInstance()->request(status.req, this);
        }else{
            distribute(status.req, this);
        }
        break;
    }
    case IPPROTO_ICMP:{
        assert(pac->icmp->gettype() == ICMP_ECHO);
        int headlen = sprintf(buff, "PING %s" CRLF CRLF,
                              getRdns(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(pac, header->request_id));
        status.req = std::make_shared<HttpReq>(header,
                                                std::bind(&Guest_vpn::response, this, (void*)id, _1),
                                                [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    case IPPROTO_ICMPV6:{
        assert(pac->icmp6->gettype() == ICMP6_ECHO_REQUEST);
        int headlen = sprintf(buff, "PING %s" CRLF CRLF,
                              getRdns(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(pac, header->request_id));
        status.req = std::make_shared<HttpReq>(header,
                                                std::bind(&Guest_vpn::response, this, (void*)id, _1),
                                                [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    default:
        abort();
    }
}


void Guest_vpn::handle(uint64_t id, ChannelMessage::Signal s) {
    auto& status = statusmap.at(id);
    LOGD(DVPN, "<guest_vpn> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
    switch(s){
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        trwer->sendMsg(id, TUN_MSG_BLOCK);
        Clean(id, status);
        break;
    }
}

void Guest_vpn::Clean(uint64_t id, VpnStatus& status) {
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.req->send(ChannelMessage::CHANNEL_ABORT);
    }
    if(status.res){
        status.res->detach();
    }
    statusmap.erase(id);
}

void Guest_vpn::dump_stat(Dumper dp, void *param) {
    dp(param, "Guest_vpn %p, session: %zd\n", this, statusmap.size());
    for(auto& i: statusmap){
        dp(param, "  0x%lx [%" PRIu32 "]: %s %s, time: %dms, flags: 0x%08x\n",
           i.first, i.second.req->header->request_id,
           i.second.req->header->method,
           i.second.req->header->geturl().c_str(),
           getmtime() - i.second.req->header->ctime,
           i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Guest_vpn::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        req_usage += i.second.req->mem_usage() + sizeof(Ip6);
    }
    dp(param, "Guest_vpn %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this),
       req_usage, rwer->mem_usage());
}