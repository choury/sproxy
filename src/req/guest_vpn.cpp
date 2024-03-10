#include "guest_vpn.h"
#include "guest.h"
#include "guest_sni.h"
#ifdef HAVE_QUIC
#include "guest3.h"
#endif
#include "res/fdns.h"
#include "prot/tls.h"
#include "prot/sslio.h"
#include "prot/tcpip/tunio.h"
#include "misc/config.h"
#include "misc/util.h"
#include "misc/strategy.h"
#include "common/version.h"

#include <fstream>
#include <sstream>
#include <assert.h>
#include <inttypes.h>

extern "C" void vpn_stop();
Guest_vpn::Guest_vpn(int fd): Requester(nullptr) {
    init(std::make_shared<TunRWer>(fd,
        [this](uint64_t id, std::shared_ptr<const Ip> pac){
            return ReqProc(id, pac);
        },
        [](int ret, int code){
            LOGE("vpn_server error: %d/%d\n", ret, code);
            vpn_stop();
        }
    ));
    rwer->SetReadCB([this](Buffer bb) -> size_t {
        if(statusmap.count(bb.id) == 0){
            return 0;
        }
        auto& status = statusmap[bb.id];
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        LOGD(DVPN, " <guest_vpn> [%" PRIu64 "] read %zd bytes\n", bb.id, bb.len);
        auto len = bb.len;

        if(len == 0) {
            if(status.req){
                status.req->send(nullptr);
            }
            if(status.rwer) {
                status.rwer->push(Buffer{nullptr, bb.id});
            }
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                Clean(bb.id);
            }
            return 0;
        }
        if(status.rwer) {
            if(status.rwer->bufsize() < len) {
                LOG("[%" PRIu64 "]: <guest_vpn> the guest's buff is full, drop packet [%zd]: %s\n", bb.id, bb.len, status.host.c_str());
                return len;
            }
            status.rwer->push(std::move(bb));
        }
        if(status.req){
            if(status.req->cap() < (int)len){
                LOG("[%" PRIu32 "]: <guest_vpn> the host's buff is full, drop packet [%zd] (%s)\n",
                    status.req->header->request_id, len, status.req->header->geturl().c_str());
                return len;
            }
            status.req->send(std::move(bb));
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
            Clean(id);
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
            auto header = std::dynamic_pointer_cast<HttpResHeader>(std::get<std::shared_ptr<HttpHeader>>(msg.data));
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
            status.cleanJob = AddJob(([this, id]{Clean(id);}), 0, 0);
            return 0;
        }
        case ChannelMessage::CHANNEL_MSG_DATA: {
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            Buffer bb = std::move(std::get<Buffer>(msg.data));
            bb.id = id;
            if (bb.len == 0) {
                LOGD(DVPN, "<guest_vpn> [%" PRIu32 "] recv data (%" PRIu64"): EOF\n",
                     status.req->header->request_id, id);
                rwer->Send({nullptr, id});
                status.flags |= HTTP_RES_COMPLETED;
                if (status.flags & HTTP_REQ_COMPLETED) {
                    status.cleanJob = AddJob(([this, id]{Clean(id);}), 0, 0);
                }
            } else {
                LOGD(DVPN, "<guest_vpn> [%" PRIu32 "] recv data (%" PRIu64"): %zu\n",
                     status.req->header->request_id, id, bb.len);
                rwer->Send(std::move(bb));
            }
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            handle(id, std::get<Signal>(msg.data));
            return 0;
        }
        return 0;
    }, [this, id]{ return rwer->cap(id);});
}

int Guest_vpn::mread(uint64_t id, std::variant<Buffer, Signal> data) {
    if(statusmap.count(id) == 0) {
        errno = EPIPE;
        return -1;
    }
    return std::visit([this, id](auto&& arg) -> int {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, Signal>) {
            handle(id, arg);
        } if constexpr (std::is_same_v<T, Buffer>) {
            auto& status = statusmap.at(id);
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            //std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            if (arg.len == 0) {
                LOGD(DVPN, "<guest_vpn> [%" PRIu64"] recv data: EOF\n", id);
                rwer->Send({nullptr, id});
                status.flags |= HTTP_RES_COMPLETED;
                if(status.flags & HTTP_REQ_COMPLETED) {
                    status.cleanJob = AddJob(([this, id]{Clean(id);}), 0, 0);
                }
                return 0;
            }
            int cap = rwer->cap(id);
            if(cap <= 0) {
                errno = EAGAIN;
                return -1;
            }
            size_t len = std::min(arg.len, (size_t)cap);
            LOGD(DVPN, "<guest_vpn> [%" PRIu64"] recv data: %zu, handle: %zu\n", id, arg.len, len);
            arg.id = id;
            arg.truncate(len);
            rwer->Send(std::move(arg));
            return (int)len;
        }
        return 0;
    }, data);
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
    bool shouldMitm = (opt.mitm_mode == Enable) ||
                      (opt.mitm_mode == Auto && opt.ca.key && mayBeBlocked(status.host.c_str()));
    switch(pac->gettype()){
    case IPPROTO_TCP:{
        if(dport == HTTPPORT) {
            status.rwer = std::make_shared<MemRWer>(
                    storage_ntoa(&src),
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id]{return rwer->cap(id);});
            new Guest(status.rwer);
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else if(dport == HTTPSPORT) {
            if(shouldMitm || getstrategy(status.host.c_str()).s == Strategy::local) {
                auto ctx = initssl(0, status.host.c_str());
                auto wrwer = std::make_shared<SslMer>(
                        ctx, storage_ntoa(&src),
                        [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                        [this, id]{return rwer->cap(id);});
                wrwer->set_server_name(status.host);
                status.rwer = wrwer;
                new Guest(wrwer);
            } else {
                status.rwer = std::make_shared<MemRWer>(
                        storage_ntoa(&src),
                        [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                        [this, id]{return rwer->cap(id);});
                new Guest_sni(status.rwer, status.host, generateUA(status.prog, 0));
            }
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else {
            //create a http proxy request
            int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF CRLF,
                                getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(status.prog, header->request_id));
            status.req = std::make_shared<HttpReq>(header, 
                            [this, id](std::shared_ptr<HttpRes> res){return response((void*)id, res);},
                            [this, id]{rwer->Unblock(id);});
            distribute(status.req, this);
        }
        break;
    }
    case IPPROTO_UDP:{
        if(dport == DNSPORT) {
            status.flags |= VPN_DNSREQ_F;
            auto mrwer = std::make_shared<PMemRWer>(
                    storage_ntoa(&src),
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id]{return rwer->cap(id);});
            FDns::GetInstance()->query(mrwer);
            status.rwer = mrwer;
#ifdef HAVE_QUIC
        } else if (dport == HTTPSPORT) {
            if(shouldMitm || getstrategy(status.host.c_str()).s == Strategy::local) {
                auto ctx = initssl(1, status.host.c_str());
                auto wrwer = std::make_shared<QuicMer>(
                        ctx, storage_ntoa(&src),
                        [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                        [this, id] { return rwer->cap(id); });
                status.rwer = wrwer;
                new Guest3(wrwer);
            } else {
                status.rwer = std::make_shared<PMemRWer>(
                        storage_ntoa(&src),
                        [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                        [this, id]{return rwer->cap(id);});
                new Guest_sni(status.rwer, status.host, generateUA(status.prog, 0));
            }
#endif
        } else {
            //create a http proxy request
            int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: udp" CRLF CRLF,
                                  getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(status.prog, header->request_id));
            status.req = std::make_shared<HttpReq>(
                    header,
                    [this, id](std::shared_ptr<HttpRes> res){return response((void*)id, res);},
                    [this, id]{rwer->Unblock(id);});
            distribute(status.req, this);
        }
        break;
    }
    case IPPROTO_ICMP:{
        assert(pac->icmp->gettype() == ICMP_ECHO);
        int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: icmp" CRLF CRLF,
                              getRdnsWithPort(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(status.prog, header->request_id));
        status.req = std::make_shared<HttpReq>(
                header,
                [this, id](std::shared_ptr<HttpRes> res){return response((void*)id, res);},
                [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    case IPPROTO_ICMPV6:{
        assert(pac->icmp6->gettype() == ICMP6_ECHO_REQUEST);
        int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: icmp" CRLF CRLF,
                              getRdnsWithPort(pac->getdst()).c_str());
        std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
        header->set("User-Agent", generateUA(status.prog, header->request_id));
        status.req = std::make_shared<HttpReq>(
                header,
                [this, id](std::shared_ptr<HttpRes> res){return response((void*)id, res);},
                [this, id]{rwer->Unblock(id);});
        distribute(status.req, this);
        break;
    }
    default:
        abort();
    }
}


void Guest_vpn::handle(uint64_t id, Signal s) {
    auto& status = statusmap.at(id);
    if (status.req) {
        LOGD(DVPN, "<guest_vpn> signal [%d] %" PRIu32 ": %d\n",
             (int) id, status.req->header->request_id, (int) s);
    } else if(status.rwer) {
        LOGD(DVPN, "<guest_vpn> signal [%d] %s: %d\n",
             (int) id, status.rwer->getPeer(), (int) s);
    }
    std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
    switch(s){
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F | TUN_CLOSED_F;
        trwer->sendMsg(id, TUN_MSG_BLOCK);
        Clean(id);
        break;
    }
}

void Guest_vpn::Clean(uint64_t id) {
    auto& status = statusmap.at(id);
    if(status.rwer && (status.flags & HTTP_CLOSED_F) == 0) {
        status.rwer->push(CHANNEL_ABORT);
    }
    if(status.req && (status.flags & HTTP_CLOSED_F) == 0){
        status.req->send(CHANNEL_ABORT);
    }

    if(status.res) {
        status.res->detach();
    }
    if(status.rwer) {
        status.rwer->detach();
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
