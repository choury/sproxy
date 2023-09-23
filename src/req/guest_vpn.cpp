#include "guest_vpn.h"
#include "guest.h"
#include "guest_sni.h"
#include "res/fdns.h"
#include "prot/tls.h"
#include "prot/sslio.h"
#include "prot/tcpip/tunio.h"
#include "misc/config.h"
#include "misc/util.h"
#include "misc/strategy.h"

#include <fstream>
#include <sstream>
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
    rwer->SetReadCB([this](const Buffer& bb) -> size_t {
        if(statusmap.count(bb.id) == 0){
            return 0;
        }
        auto& status = statusmap[bb.id];
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        LOGD(DVPN, " <guest_vpn> [%" PRIu64 "] read %zd bytes\n", bb.id, bb.len);

        if(bb.len == 0) {
            if(status.req){
                status.req->send(nullptr);
            }
            if(status.rwer) {
                status.rwer->push({nullptr, bb.id});
            }
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                Clean(bb.id, status);
            }
            return 0;
        }
        if(status.rwer) {
            if(status.rwer->cap(0) < (int)bb.len) {
                LOG("[%" PRIu64 "]: <guest_vpn> the guest's buff is full, drop packet [%zd]: %s\n", bb.id, bb.len, status.host.c_str());
                return bb.len;
            }
            status.rwer->push({bb.data(), bb.len});
        }
        if(status.req){
            if(status.req->cap() < (int)bb.len){
                LOG("[%" PRIu32 "]: <guest_vpn> the host's buff is full, drop packet [%zd] (%s)\n",
                    status.req->header->request_id, bb.len, status.req->header->geturl().c_str());
                return bb.len;
            }
            status.req->send(bb.data(), bb.len);
        }
        return 0;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        auto& status = statusmap[id];
        if((status.flags & HTTP_RES_COMPLETED) == 0){
            if(status.res)
                status.res->pull();
            if(status.rwer)
                status.rwer->Unblock(0);
        }
    });
    std::dynamic_pointer_cast<TunRWer>(rwer)->setResetHandler([this](uint64_t id, uint32_t){
        if(statusmap.count(id)) {
            auto& status = statusmap[id];
            LOGD(DVPN, " <guest_vpn> [%" PRIu64 "] reset\n", id);
            status.flags |= TUN_CLOSED_F;
            Clean(id, status);
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
#else
static const char* getProg(std::shared_ptr<const Ip>) {
    return "<Unknown>";
}
#endif

static std::string generateUA(const std::string& prog, uint32_t request_id) {
    std::stringstream UA;
    if(opt.ua){
        UA << opt.ua << " Sproxy/" << getVersion();
    } else {
#ifdef __ANDROID__
        UA << "Sproxy/" << getVersion()
           << " (Build " << getBuildTime() << ") "
           <<"(" << getDeviceName() << ") " << prog
           << " App/" << appVersion;
#else
        UA << "Sproxy/" << getVersion()
           << " (Build " << getBuildTime() << ") "
           <<"(" << getDeviceInfo() << ") " << prog;
#endif
    }

    if (request_id != 0) {
        UA << " SEQ/" << request_id;
    }
    return UA.str();
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
                status.flags |= TUN_CLOSED_F;
            }else if(header->status[0] == '5'){
                trwer->sendMsg(id, TUN_MSG_UNREACH);
                status.flags |= TUN_CLOSED_F;
            }else{
                LOGE("unknown response\n");
            }
            status.res->detach();
            AddJob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
            return 0;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            msg.data.id = id;
            if (msg.data.len == 0) {
                LOGD(DVPN, "<guest_vpn> [%" PRIu32 "] recv data (%" PRIu64"): EOF\n",
                     status.req->header->request_id, id);
                rwer->buffer_insert({nullptr, id});
                status.flags |= HTTP_RES_COMPLETED;
                if(status.flags & HTTP_REQ_COMPLETED) {
                    AddJob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
                }
            }else{
                LOGD(DVPN, "<guest_vpn> [%" PRIu32 "] recv data (%" PRIu64"): %zu\n",
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

int Guest_vpn::mread(uint64_t id, Buffer && bb) {
    if(statusmap.count(id) == 0) {
        errno = EPIPE;
        return -1;
    }
    auto& status = statusmap.at(id);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    //std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
    if (bb.len == 0) {
        LOGD(DVPN, "<guest_vpn> [%" PRIu64"] recv data: EOF\n", id);
        rwer->buffer_insert({nullptr, id});
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED) {
            AddJob(std::bind(&Guest_vpn::Clean, this, id, status), 0, JOB_FLAGS_AUTORELEASE);
        }
        return 0;
    }
    int cap = rwer->cap(id);
    if(cap <= 0) {
        errno = EAGAIN;
        return -1;
    }
    size_t len = std::min(bb.len, (size_t)cap);
    LOGD(DVPN, "<guest_vpn> [%" PRIu64"] recv data: %zu, handle: %zu\n", id, bb.len, len);
    bb.id = id;
    bb.truncate(len);
    rwer->buffer_insert(std::move(bb));
    return len;
}

void Guest_vpn::ReqProc(uint64_t id, std::shared_ptr<const Ip> pac) {
    assert(statusmap.count(id) == 0);
    statusmap.emplace(id, VpnStatus{});
    auto& status = statusmap[id];
    status.host = getRdns(pac->getdst());
    status.prog = getProg(pac);
    status.pac = pac;
    char buff[HEADLENLIMIT];
    uint16_t dport = pac->getdport();
    auto src = pac->getsrc();
    switch(pac->gettype()){
    case IPPROTO_TCP:{
        if(dport == HTTPPORT) {
            status.rwer = std::make_shared<MemRWer>(storage_ntoa(&src),
                                                    std::bind(&Guest_vpn::mread, this, id, _1),
                                                    [this, id]{return rwer->cap(id);});
            new Guest(status.rwer);
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else if(dport == HTTPSPORT) {
            auto stra = getstrategy(status.host.c_str());
            if(stra.s == Strategy::local || (opt.ca.key && mayBeBlocked(status.host.c_str()))) {
                auto ctx = initssl(0, status.host.c_str());
                auto wrwer = std::make_shared<SslRWer<MemRWer>>(ctx, storage_ntoa(&src),
                                                                std::bind(&Guest_vpn::mread, this, id, _1),
                                                                [this, id]{return rwer->cap(id);});
                wrwer->set_server_name(status.host);
                status.rwer = wrwer;
                new Guest(wrwer);
            } else {
                status.rwer = std::make_shared<MemRWer>(storage_ntoa(&src),
                                                        std::bind(&Guest_vpn::mread, this, id, _1),
                                                        [this, id]{return rwer->cap(id);});
                new Guest_sni(status.rwer, status.host, generateUA(status.prog, 0));
            }
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else {
            //create a http proxy request
            int headlen = sprintf(buff, "CONNECT %s" CRLF CRLF,
                                getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(status.prog, header->request_id));
            status.req = std::make_shared<HttpReq>(header, 
                            std::bind(&Guest_vpn::response, this, (void*)id, _1), 
                            [this, id]{rwer->Unblock(id);});
            distribute(status.req, this);
        }
        break;
    }
    case IPPROTO_UDP:{
        if(dport == DNSPORT) {
            status.flags |= VPN_DNSREQ_F;
            auto mrwer = std::make_shared<PMemRWer>(storage_ntoa(&src),
                                                    std::bind(&Guest_vpn::mread, this, id, _1),
                                                    [this, id]{return rwer->cap(id);});
            FDns::GetInstance()->query(mrwer);
            status.rwer = mrwer;
        } else {
            //create a http proxy request
            int headlen = sprintf(buff, "SEND %s" CRLF CRLF,
                                  getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(status.prog, header->request_id));
            status.req = std::make_shared<HttpReq>(header,
                                                   std::bind(&Guest_vpn::response, this, (void*)id, _1),
                                                   [this, id]{rwer->Unblock(id);});
            distribute(status.req, this);
        }
        break;
    }
    case IPPROTO_ICMP:{
        assert(pac->icmp->gettype() == ICMP_ECHO);
        int headlen = sprintf(buff, "PING %s" CRLF CRLF,
                              getRdnsWithPort(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(status.prog, header->request_id));
        status.req = std::make_shared<HttpReq>(header,
                                                std::bind(&Guest_vpn::response, this, (void*)id, _1),
                                                [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    case IPPROTO_ICMPV6:{
        assert(pac->icmp6->gettype() == ICMP6_ECHO_REQUEST);
        int headlen = sprintf(buff, "PING %s" CRLF CRLF,
                              getRdnsWithPort(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(status.prog, header->request_id));
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
        status.flags |= HTTP_CLOSED_F | TUN_CLOSED_F;
        trwer->sendMsg(id, TUN_MSG_BLOCK);
        Clean(id, status);
        break;
    }
}

void Guest_vpn::Clean(uint64_t id, VpnStatus& status) {
    if(status.rwer) {
        if ((status.flags & HTTP_REQ_COMPLETED) == 0 && (status.flags & HTTP_RES_COMPLETED)){
            status.rwer->push({nullptr});
        }else {
            status.rwer->injection(PEER_LOST_ERR, 0);
        }
        status.rwer->detach();
    }
    if(status.req && (status.flags & HTTP_CLOSED_F) == 0){
        status.req->send(ChannelMessage::CHANNEL_ABORT);
    }

    if(status.res) {
        status.res->detach();
    }
    statusmap.erase(id);
}

void Guest_vpn::dump_stat(Dumper dp, void *param) {
    dp(param, "Guest_vpn %p, session: %zd\n", this, statusmap.size());
    for(auto& i: statusmap){
        if(i.second.req) {
            dp(param, "  0x%lx [%" PRIu32 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
                i.first, i.second.req->header->request_id,
                i.second.req->header->method,
                i.second.req->header->geturl().c_str(),
                getmtime() - i.second.req->header->ctime,
                i.second.flags, i.second.prog.c_str());
        }
        if(i.second.rwer) {
            auto src = i.second.pac->getsrc();
            dp(param, "  0x%lx [MemRWer]: %s, flags: 0x%08x [%s]\n",
                i.first, storage_ntoa(&src), i.second.flags, i.second.prog.c_str());

        }
    }
    rwer->dump_status(dp, param);
}

void Guest_vpn::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        //res 对象不由 Guest_vpn 计算，而由Responser统计
        //rwer 对象也不由 Guest_vpn 计算，而由Guest统计
        if(i.second.req) {
            req_usage += i.second.req->mem_usage() + sizeof(Ip6);
        }
    }
    dp(param, "Guest_vpn %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this),
       req_usage, rwer->mem_usage());
}
