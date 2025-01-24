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
Guest_vpn::Guest_vpn(int fd, bool enable_offload): Requester(nullptr) {
    rwer = std::make_shared<TunRWer>(fd, enable_offload,
        [this](uint64_t id, std::shared_ptr<const Ip> pac){
            return ReqProc(id, pac);
        },
        [](int ret, int code){
            LOGE("vpn_server error: %d/%d\n", ret, code);
            exit_loop();
        }
    );
    rwer->SetReadCB([this](Buffer&& bb) -> size_t {
        if(statusmap.count(bb.id) == 0){
            LOG("[%" PRIu64 "]: <guest_vpn> id not found, discard all\n", bb.id);
            return bb.len;
        }
        auto& status = statusmap[bb.id];
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        LOGD(DVPN, "<guest_vpn> [%" PRIu64 "] read %zd bytes, refs:%zd\n", bb.id, bb.len, bb.refs());
        if(bb.len == 0) {
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
        auto len = bb.len;
        if(status.rwer) {
            if(status.rwer->bufsize() < len) {
                LOG("[%" PRIu64 "]: <guest_vpn> the guest's buff is full, skip packet [%zd]: %s\n",
                    bb.id, len, status.host.c_str());
                return 0;
            }
            status.rwer->push(std::move(bb));
        }
        if(status.req){
            if(status.req->cap() < (int)len){
                LOG("[%" PRIu64 "]: <guest_vpn> the host's buff is full, skip packet [%zd] (%s)\n",
                    status.req->header->request_id, len, status.req->header->geturl().c_str());
                return 0;
            }
            status.req->send(std::move(bb));
        }
        return len;
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
                status.rwer->pull(id);
        }
    });
    std::dynamic_pointer_cast<TunRWer>(rwer)->setResetHandler([this](uint64_t id, uint32_t){
        if(statusmap.count(id)) {
            LOGD(DVPN, "<guest_vpn> [%" PRIu64 "] reset\n", id);
            auto& status = statusmap[id];
            status.flags |= TUN_CLOSED_F;
            Clean(id);
        } else {
            LOGD(DVPN, "<guest_vpn> [%" PRIu64 "] reset, but not found\n", id);
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
    if(src_.ss_family == AF_INET){
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
    if(src_.ss_family == AF_INET){
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

void Guest_vpn::response(void* index, std::shared_ptr<HttpRes> res) {
    uint64_t id = (uint64_t)index;
    auto& status = statusmap.at(id);
    assert(status.res == nullptr);
    status.res = res;
    res->attach([this, id](ChannelMessage&& msg) -> int{
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
                LOGD(DVPN, "<guest_vpn> [%" PRIu64 "] recv data (%" PRIu64"): EOF\n",
                     status.req->header->request_id, id);
                rwer->Send({nullptr, id});
                status.flags |= HTTP_RES_COMPLETED;
                if (status.flags & HTTP_REQ_COMPLETED) {
                    status.cleanJob = AddJob(([this, id]{Clean(id);}), 0, 0);
                }
            } else {
                LOGD(DVPN, "<guest_vpn> [%" PRIu64 "] recv data (%" PRIu64"): %zu\n",
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

int Guest_vpn::mread(uint64_t id, std::variant<std::reference_wrapper<Buffer>, Buffer, Signal> data) {
    if(statusmap.count(id) == 0) {
        errno = EPIPE;
        return -1;
    }
    auto BufferHandle = [this](uint64_t id, Buffer& bb) {
        auto& status = statusmap.at(id);
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        //std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
        if (bb.len == 0) {
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
        LOGD(DVPN, "<guest_vpn> [%" PRIu64"] recv data: %zu, refs: %zd, cap: %d\n",
             id, bb.len, bb.refs(), cap);
        if(cap >= (int)bb.len) {
            cap = bb.len;
            auto cbb = std::move(bb);
            cbb.id = id;
            rwer->Send(std::move(cbb));
        }else {
            auto cbb = bb;
            cbb.id = id;
            cbb.truncate(cap);
            rwer->Send(std::move(cbb));
        }
        return cap;
    };
    return std::visit([&](auto&& arg) -> int {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, Signal>) {
            handle(id, arg);
        }else if constexpr (std::is_same_v<T, Buffer>) {
            return BufferHandle(id, arg);
        }else if constexpr (std::is_same_v<T, std::reference_wrapper<Buffer>>) {
            return BufferHandle(id, arg.get());
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
    Destination addr{};
    storage2Dest(&src, &addr);
    bool shouldMitm = isFakeIp(pac->getdst()) && shouldNegotiate(status.host);
    switch(pac->gettype()){
    case IPPROTO_TCP:{
        if(dport == HTTPPORT) {
            status.rwer = std::make_shared<MemRWer>(
                addr,
                [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                [this, id] { return rwer->cap(id); });
            new Guest(status.rwer);
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else if(dport == HTTPSPORT) {
            if(shouldMitm || getstrategy(status.host.c_str()).s == Strategy::local) {
                auto ctx = initssl(0, status.host.c_str());
                auto wrwer = std::make_shared<SslMer>(
                    ctx, addr,
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id] { return rwer->cap(id); });
                wrwer->set_server_name(status.host);
                status.rwer = wrwer;
                new Guest(wrwer);
            } else {
                status.rwer = std::make_shared<MemRWer>(
                    addr,
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id] { return rwer->cap(id); });
                new Guest_sni(status.rwer, status.host, generateUA(opt.ua, status.prog, 0).c_str());
            }
            std::shared_ptr<TunRWer> trwer = std::dynamic_pointer_cast<TunRWer>(rwer);
            trwer->sendMsg(id, TUN_MSG_SYN);
        } else {
            //create a http proxy request
            int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF CRLF,
                                getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(opt.ua, status.prog, header->request_id));
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
                addr,
                [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                [this, id] { return rwer->cap(id); });
            FDns::GetInstance()->query(id, mrwer);
            status.rwer = mrwer;
#ifdef HAVE_QUIC
        } else if (dport == HTTPSPORT) {
            if(shouldMitm || getstrategy(status.host.c_str()).s == Strategy::local) {
                auto ctx = initssl(1, status.host.c_str());
                auto wrwer = std::make_shared<QuicMer>(
                    ctx, addr,
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id] { return rwer->cap(id); });
                status.rwer = wrwer;
                new Guest3(wrwer);
            } else {
                status.rwer = std::make_shared<PMemRWer>(
                    addr,
                    [this, id](auto&& data) { return mread(id, std::forward<decltype(data)>(data)); },
                    [this, id] { return rwer->cap(id); });
                new Guest_sni(status.rwer, status.host, generateUA(opt.ua, status.prog, 0).c_str());
            }
#endif
        } else {
            //create a http proxy request
            int headlen = snprintf(buff, sizeof(buff), "CONNECT %s" CRLF "Protocol: udp" CRLF CRLF,
                                  getRdnsWithPort(pac->getdst()).c_str());

            std::shared_ptr<HttpReqHeader> header = UnpackHttpReq(buff, headlen);
            header->set("User-Agent", generateUA(opt.ua, status.prog, header->request_id));
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
        header->set("User-Agent", generateUA(opt.ua, status.prog, header->request_id));
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
        header->set("User-Agent", generateUA(opt.ua, status.prog, header->request_id));
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
        LOGD(DVPN, "<guest_vpn> signal [%d] %" PRIu64 ": %d\n",
             (int) id, status.req->header->request_id, (int) s);
    } else if(status.rwer) {
        LOGD(DVPN, "<guest_vpn> signal [%d] %s: %d\n",
             (int) id, dumpDest(status.rwer->getSrc()).c_str(), (int) s);
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
            dp(param, "  0x%lx [%" PRIu64 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
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
