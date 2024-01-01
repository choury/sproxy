#include "common/common.h"
#include "tunio.h"
#include "misc/pcap.h"
#include "misc/config.h"
#include "misc/util.h"
#include "res/fdns.h"

#include <errno.h>
#include <inttypes.h>

VpnKey::VpnKey(std::shared_ptr<const Ip> ip) {
    src = ip->getsrc();
    dst = ip->getdst();
    switch(ip->gettype()){
    case IPPROTO_TCP:
        protocol = Protocol::TCP;
        break;
    case IPPROTO_UDP:
        protocol = Protocol::UDP;
        break;
    case IPPROTO_ICMP:
        protocol = Protocol::ICMP;
        break;
    case IPPROTO_ICMPV6:
        protocol = Protocol::ICMP;
        break;
    default:
        protocol = Protocol::NONE;
        break;
    }
}

const VpnKey& VpnKey::reverse() {
    auto tmp  = dst;
    dst = src;
    src = tmp;
    return *this;
}

static bool operator<(const sockaddr_storage& a, const sockaddr_storage& b) {
    return memcmp(&a, &b, sizeof(sockaddr_storage)) < 0;
}

bool operator<(const VpnKey& a, const VpnKey& b) {
    return std::tie(a.protocol, a.src, a.dst) < std::tie(b.protocol, b.src, b.dst);
}

#define ICMP_PING(type) ((type) == ICMP_ECHO || (type) == ICMP_ECHOREPLY)
#define ICMP6_PING(type)  ((type) == ICMP6_ECHO_REQUEST || (type) == ICMP6_ECHO_REPLY)

void debugString(std::shared_ptr<const Ip> pac, size_t len) {
    switch(pac->gettype()){
    case IPPROTO_TCP:
        LOGD(DVPN, "<tcp> (%s -> %s) (%u - %u) flag: %s size:%zu\n",
             getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
             pac->tcp->getseq(), pac->tcp->getack(), pac->tcp->getflags(), len);
        return;
    case IPPROTO_UDP:
        LOGD(DVPN, "<udp> (%s -> %s) size:%zu\n",
             getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(), len);
        return;
    case IPPROTO_ICMP:
        if(ICMP_PING(pac->icmp->gettype())){
            LOGD(DVPN, "<ping> (%s -> %s) (%u) size:%zu\n",
                 getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                 pac->icmp->getseq(), len);
        } else {
            LOGD(DVPN, "<icmp> (%s -> %s) (%u) size:%zu\n",
                 getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                 pac->icmp->gettype(), len);
        }
        return;
    case IPPROTO_ICMPV6:
        if(ICMP6_PING(pac->icmp6->gettype())) {
            LOGD(DVPN, "<ping6> (%s -> %s) (%u) size:%zu\n",
                 getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                 pac->icmp6->getseq(), len);
        }else {
            LOGD(DVPN, "<icmp6> (%s -> %s) (%u) size:%zu\n",
                 getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                 pac->icmp6->gettype(), len);
        }
        return;
    default:
        break;
    }
    pac->dump();
}

uint64_t TunRWer::GetId(std::shared_ptr<const Ip> pac) {
    return statusmap.GetOne(VpnKey(pac))->first.first;
}

std::shared_ptr<IpStatus> TunRWer::GetStatus(uint64_t id) {
    return statusmap.GetOne(id)->second;
}

TunRWer::TunRWer(int fd, std::function<void(uint64_t, std::shared_ptr<const Ip>)> reqProc,
                 std::function<void(int ret, int code)> errorCB):
    RWer(fd, errorCB), reqProc(reqProc)
{
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&TunRWer::defaultHE;
    if(opt.pcap_file) {
        pcap = pcap_create(opt.pcap_file);
    }
};

TunRWer::~TunRWer(){
    for(auto& itr : statusmap.data()){
        itr.second->PkgProc = nullptr;
        itr.second->SendPkg = nullptr;
        itr.second->UnReach = nullptr;
        itr.second->Cap = nullptr;
    }
    statusmap.clear();
    pcap_close(pcap);
}

void TunRWer::ReadData() {
    int ret = 0;
    while(ret = read(getFd(), rbuff, sizeof(rbuff)), ret > 0) {
        if(ret <= 0 && errno == EAGAIN) {
            return;
        }
        if(ret <= 0) {
            ErrorHE(SOCKET_ERR, errno);
            return;
        }
        size_t len = ret;
        pcap_write_with_generated_ethhdr(pcap, rbuff, len);
        auto pac = MakeIp(rbuff, ret);
        if(pac == nullptr){
            continue;
        }
        debugString(pac, len - pac->gethdrlen());
        VpnKey key(pac);

        bool transIcmp = false;
        if(pac->gettype() == IPPROTO_ICMP) {
            uint16_t type = pac->icmp->gettype();
            if(type ==  ICMP_UNREACH) {
                auto icmp_pac = MakeIp(rbuff + pac->gethdrlen(), len-pac->gethdrlen());
                if(icmp_pac == nullptr){
                    continue;
                }
                transIcmp = true;
                key = VpnKey(icmp_pac).reverse();
                LOGD(DVPN, "get icmp unreach for: <%s> %s - %s\n",
                     protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
            }else if(!ICMP_PING(type)) {
                LOGD(DVPN, "ignore icmp type: %d\n", type);
                continue;
            }
        }else if(pac->gettype() == IPPROTO_ICMPV6) {
            uint16_t type = pac->icmp6->gettype();
            if(type == ICMP6_DST_UNREACH){
                auto icmp6_pac = MakeIp(rbuff + pac->gethdrlen(), len-pac->gethdrlen());
                if(icmp6_pac == nullptr){
                    continue;
                }
                transIcmp = true;
                key = VpnKey(icmp6_pac).reverse();
                LOGD(DVPN, "get icmp6 unreach for: <%s> %s - %s\n",
                     protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
            }else if(!ICMP6_PING(type)) {
                LOGD(DVPN, "ignore icmp6 type: %d\n", type);
                continue;
            }
        }
        std::shared_ptr<IpStatus> status;
        if(!statusmap.Has(key)){
            if(transIcmp) {
                continue;
            }
            switch(key.protocol){
            case Protocol::TCP:{
                auto tstatus = std::make_shared<TcpStatus>();
                tstatus->PkgProc = std::bind(SynProc, tstatus, _1, _2, _3);
                tstatus->SendPkg = std::bind((void(*)(std::shared_ptr<TcpStatus>, Buffer&&))::SendData, tstatus, _1);
                tstatus->UnReach = std::bind((void (*)(std::shared_ptr<TcpStatus>, uint8_t)) UnReach, tstatus, _1);
                tstatus->Cap = std::bind((ssize_t(*)(std::shared_ptr<TcpStatus>))Cap, tstatus);
                status = tstatus;
                break;
            }
            case Protocol::UDP:{
                auto ustatus = std::make_shared<UdpStatus>();
                ustatus->PkgProc = std::bind(UdpProc, ustatus, _1, _2, _3);
                ustatus->SendPkg = std::bind((void(*)(std::shared_ptr<UdpStatus>, Buffer&&))::SendData, ustatus, _1);
                ustatus->UnReach = std::bind((void(*)(std::shared_ptr<IpStatus>, uint8_t))Unreach, ustatus, _1);
                ustatus->Cap = std::bind((ssize_t(*)(std::shared_ptr<IpStatus>))Cap, ustatus);
                status = ustatus;
                break;
            }
            case Protocol::ICMP:{
                auto istatus = std::make_shared<IcmpStatus>();
                istatus->PkgProc = std::bind(IcmpProc, istatus, _1, _2, _3);
                istatus->SendPkg = std::bind((void(*)(std::shared_ptr<IcmpStatus>, Buffer&&))::SendData, istatus, _1);
                istatus->UnReach = std::bind((void(*)(std::shared_ptr<IpStatus>, uint8_t))Unreach, istatus, _1);
                istatus->Cap = std::bind((ssize_t(*)(std::shared_ptr<IpStatus>))Cap, istatus);
                status = istatus;
                break;
            }
            case Protocol::NONE:
                LOGD(DVPN, "ignore unknow protocol: %d\n", pac->gettype());
                continue;
            default:
                continue;
            }
            status->reqCB = std::bind(&TunRWer::ReqProc, this, _1);
            status->dataCB = std::bind(&TunRWer::DataProc, this, _1, _2, _3);
            status->ackCB = std::bind(&TunRWer::AckProc, this, _1);
            status->errCB = std::bind(&TunRWer::ErrProc, this, _1, _2);
            status->sendCB = std::bind(&TunRWer::SendPkg, this, _1, _2, _3);
            status->protocol = key.protocol;
            status->src = pac->getsrc();
            status->dst = pac->getdst();
            statusmap.Add(next_id++, key, status);
        }else{
            if(transIcmp){
                uint64_t id = statusmap.GetOne(key)->first.first;
                resetHanlder(id, ICMP_UNREACH_ERR);
                Clean(id);
                continue;
            }
            status = statusmap.GetOne(key)->second;
        }
        if(status->packet_hdr == nullptr){
            status->packet_hdr_len = pac->gethdrlen();
            status->packet_hdr = std::make_shared<Block>(rbuff, status->packet_hdr_len);
        }
        status->PkgProc(pac, rbuff, len);
    }
}

//只有TCP有读缓冲，所以对其他情况都返回0
size_t TunRWer::rlength(uint64_t id) {
    if(!statusmap.Has(id)) {
        return 0;
    }
    auto status = GetStatus(id);
    if (status->protocol == Protocol::TCP) {
        return 1;
    }
    return 0;
}

void TunRWer::ConsumeRData(uint64_t id) {
    assert(statusmap.Has(id));
    auto status = GetStatus(id);
    if (status->protocol == Protocol::TCP) {
        consumeData(std::static_pointer_cast<TcpStatus>(status));
    }
}

void TunRWer::SendPkg(std::shared_ptr<const Ip> pac, const void* data, size_t len) {
    debugString(pac, len - pac->gethdrlen());
    pcap_write_with_generated_ethhdr(pcap, data, len);
    (void)!write(getFd(), data, len);
}

void TunRWer::Send(Buffer&& bb) {
    if(!statusmap.Has(bb.id)){
        return;
    }
    auto status = GetStatus(bb.id);
    status->SendPkg(std::move(bb));
}

void TunRWer::ReqProc(std::shared_ptr<const Ip> pac) {
    if(reqProc){
        reqProc(GetId(pac), pac);
    }
}

void TunRWer::Clean(uint64_t id) {
    auto status = GetStatus(id);
    status->PkgProc = nullptr;
    status->SendPkg = nullptr;
    status->UnReach = nullptr;
    status->Cap = nullptr;
    statusmap.Delete(id);
}

void TunRWer::ErrProc(std::shared_ptr<const Ip> pac, uint32_t code) {
    uint64_t id = GetId(pac);
    resetHanlder(id, code);
    Clean(id);
    LOGD(DVPN, "tunio: delete id: 0x%" PRIx64", due to err: %d\n", id, (int)code);
}

size_t TunRWer::DataProc(std::shared_ptr<const Ip> pac, const void* data, size_t len) {
    if(!statusmap.Has(VpnKey(pac))){
        return 0;
    }
    if(len == 0) {
        assert(data == nullptr);
        readCB({nullptr, GetId(pac)});
        return 0;
    }
    return len - readCB({std::make_shared<Block>(data, len), len, GetId(pac)});
}

void TunRWer::AckProc(std::shared_ptr<const Ip> pac) {
    if(!statusmap.Has(VpnKey(pac))) {
        return;
    }
    auto itr = statusmap.GetOne(VpnKey(pac));
    if(itr->second->Cap() >= 0) {
        return writeCB(itr->first.first);
    }
}

void TunRWer::sendMsg(uint64_t id, uint32_t msg) {
    auto status = GetStatus(id);
    switch(msg){
    case TUN_MSG_SYN:
        if(status->protocol == Protocol::TCP) {
            SendSyn(std::static_pointer_cast<TcpStatus>(status));
        }
        break;
    case TUN_MSG_BLOCK:
        LOGD(DVPN, "tunio: delete id: 0x%" PRIx64", due to block\n", id);
        if(status->protocol == Protocol::TCP) {
            SendRst(std::static_pointer_cast<TcpStatus>(status));
        } else {
            status->UnReach(IP_ADDR_UNREACH);
        }
        Clean(id);
        break;
    case TUN_MSG_UNREACH:
        LOGD(DVPN, "tunio: delete id: 0x%" PRIx64", due to unreach\n", id);
        status->UnReach(IP_PORT_UNREACH);
        Clean(id);
        break;
    }
}

void TunRWer::setResetHandler(std::function<void (uint64_t, uint32_t)> func) {
    resetHanlder = std::move(func);
}

ssize_t TunRWer::cap(uint64_t id) {
    auto status = GetStatus(id);
    return status->Cap();
}

bool TunRWer::idle(uint64_t id) {
    return !statusmap.Has(id);
}

static void dumpConnection(Dumper dp, void* param,
                           const std::pair<const std::pair<uint64_t, VpnKey>, std::shared_ptr<IpStatus>>& value) {
    auto& status_ = value.second;
    switch(status_->protocol) {
    case Protocol::TCP: {
        auto status = std::static_pointer_cast<TcpStatus>(status_);
        dp(param, "  0x%lx: <tcp> %s -> %s, srtt=%zd, state=%d, wlist: %zd, rlen: %zd\n",
           value.first.first,
           std::string(storage_ntoa(&status->src)).c_str(),
           std::string(storage_ntoa(&status->dst)).c_str(),
           (size_t) status->srtt, status->state,
           status->sent_list.size(), status->rbuf.length());
        break;
    }
    case Protocol::UDP: {
        auto status = std::static_pointer_cast<UdpStatus>(status_);
        dp(param, "  0x%lx: <udp> %s -> %s, readlen=%zd\n",
           value.first.first,
           std::string(storage_ntoa(&status->src)).c_str(),
           std::string(storage_ntoa(&status->dst)).c_str(),
           status->readlen);
        break;
    }
    case Protocol::ICMP: {
        auto status = std::static_pointer_cast<IcmpStatus>(status_);
        dp(param, "  0x%lx: <icmp> %s -> %s, id=%d, seq=%d\n",
           value.first.first,
           std::string(storage_ntoa(&status->src)).c_str(),
           std::string(storage_ntoa(&status->dst)).c_str(),
           status->id, status->seq);
        break;
    }
    default:
        break;
    }
}

void TunRWer::dump_status(Dumper dp, void *param) {
    dp(param, "TunRwer <%d>: %p, session: %zd\n", getFd(), this, statusmap.size());
    for(const auto& status : statusmap.data()) {
        dumpConnection(dp, param, status);
    }
}

size_t TunRWer::mem_usage() {
    size_t usage = sizeof(*this);
    for(const auto& i : statusmap.data()){
        usage += sizeof(i.first) * 2 + sizeof(i.second);
        switch(i.second->protocol) {
        case Protocol::TCP: {
            auto status = std::static_pointer_cast<TcpStatus>(i.second);
            usage += sizeof(TcpStatus) + status->rbuf.cap() + status->rbuf.length();
            usage += status->sent_list.size() * sizeof(tcp_sent);
            for(const auto& sent : status->sent_list) {
                usage += sizeof(Ip6);
                usage += sent.bb.cap;
            }
            Sack* sack = status->sack;
            while(sack) {
                usage += sizeof(Sack);
                sack = sack->next;
            }
            break;
        }
        case Protocol::UDP: {
            auto status = std::static_pointer_cast<UdpStatus>(i.second);
            usage += sizeof(UdpStatus);
            break;
        }
        case Protocol::ICMP: {
            auto status = std::static_pointer_cast<IcmpStatus>(i.second);
            usage += sizeof(IcmpStatus);
            break;
        }
        default:
            break;
        }
    }
    return usage;
}
