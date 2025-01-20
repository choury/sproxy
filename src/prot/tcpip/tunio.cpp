#include "common/common.h"
#include "tunio.h"
#include "misc/pcap.h"
#include "misc/config.h"
#include "misc/util.h"
#include "res/fdns.h"

#include <errno.h>
#include <inttypes.h>

#include <utility>

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
        LOGE("Unknown proto type: %d\n", pac->gettype());
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

TunRWer::TunRWer(int fd, bool enable_offload,
                 std::function<void(uint64_t, std::shared_ptr<const Ip>)> reqProc,
                 std::function<void(int ret, int code)> errorCB):
    RWer(fd, std::move(errorCB)), enable_offload(enable_offload), reqProc(std::move(reqProc))
{
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&TunRWer::defaultHE;
    if(opt.pcap_file) {
        pcap = pcap_create(opt.pcap_file);
    }
    set_checksum_offload(enable_offload);
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
    const size_t& TUN_BUF_LEN = 65536;
    while(true) {
        Block rbuff(TUN_BUF_LEN);
        int ret = read(getFd(), rbuff.data(), TUN_BUF_LEN);
        LOGD(DVPN, "read %d bytes from tun\n", ret);
        if(ret <= 0 && errno == EAGAIN) {
            return;
        }
        size_t len = ret;
#if __linux__
        if(ret <= (int)sizeof(virtio_net_hdr_v1)) {
            ErrorHE(SOCKET_ERR, errno);
            return;
        }
        if(enable_offload) {
            auto hdr = (virtio_net_hdr_v1*)rbuff.data();
            if(hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
                LOGD(DVPN, "gso type: %d, gso size: %d, num: %d\n", hdr->gso_type, hdr->gso_size, hdr->num_buffers);
            }
            rbuff.reserve(sizeof(virtio_net_hdr_v1));
            len -= sizeof(virtio_net_hdr_v1);
        }
#endif
        pcap_write(pcap, rbuff.data(), len);
        auto pac = MakeIp(rbuff.data(), len);
        if(pac == nullptr){
            continue;
        }
        debugString(pac, len - pac->gethdrlen());
        VpnKey key(pac);

        bool transIcmp = false;
        if(pac->gettype() == IPPROTO_ICMP) {
            uint16_t type = pac->icmp->gettype();
            if(type ==  ICMP_UNREACH) {
                auto icmp_pac = MakeIp((char*)rbuff.data() + pac->gethdrlen(), len-pac->gethdrlen());
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
                auto icmp6_pac = MakeIp((char*)rbuff.data() + pac->gethdrlen(), len-pac->gethdrlen());
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
            if(pac->getdport() == 0 || pac->getsport() == 0) {
                LOG("<tunio> ignore invalid port: <%s> %s -> %s\n",
                    protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
                continue;
            }
            switch(key.protocol){
            case Protocol::TCP:{
                auto tstatus = std::make_shared<TcpStatus>();
                tstatus->PkgProc = [tstatus](auto&& v1, auto&& v2){
                    SynProc(tstatus, v1, std::forward<decltype(v2)>(v2));
                };
                tstatus->SendPkg = [tstatus](Buffer&& bb){::SendData(tstatus, std::move(bb));};
                tstatus->UnReach = [tstatus](uint8_t code){Unreach(tstatus, code);};
                tstatus->Cap = [tstatus]{return Cap(tstatus);};
                status = tstatus;
                break;
            }
            case Protocol::UDP:{
                auto ustatus = std::make_shared<UdpStatus>();
                ustatus->PkgProc = [ustatus](auto&& v1, auto&& v2){
                    UdpProc(ustatus, v1, std::forward<decltype(v2)>(v2));
                };
                ustatus->SendPkg = [ustatus](Buffer&& bb){::SendData(ustatus, std::move(bb));};
                ustatus->UnReach = [ustatus](uint8_t code){Unreach(ustatus, code);};
                ustatus->Cap = [ustatus]{return Cap(ustatus);};
                status = ustatus;
                break;
            }
            case Protocol::ICMP:{
                auto istatus = std::make_shared<IcmpStatus>();
                istatus->PkgProc = [istatus](auto&& v1, auto&& v2) {
                    IcmpProc(istatus, v1, std::forward<decltype(v2)>(v2));
                };
                istatus->SendPkg = [istatus](Buffer&& bb){::SendData(istatus, std::move(bb));};
                istatus->UnReach = [istatus](uint8_t code){Unreach(istatus, code);};
                istatus->Cap = [istatus]{return Cap(istatus);};
                status = istatus;
                break;
            }
            case Protocol::NONE:
                LOGD(DVPN, "ignore unknow protocol: %d\n", pac->gettype());
                continue;
            default:
                continue;
            }
            if(enable_offload){
                status->flags = TUN_GSO_OFFLOAD;
            }
            status->reqCB = [this](std::shared_ptr<const Ip> pac){ReqProc(pac);};
            status->dataCB = [this](std::shared_ptr<const Ip> pac, Buffer&& bb){
                return DataProc(pac, std::move(bb));
            };
            status->ackCB = [this](std::shared_ptr<const Ip> pac){AckProc(pac);};
            status->errCB = [this](std::shared_ptr<const Ip> pac, uint32_t code){ErrProc(pac, code);};
            status->sendCB = [this](std::shared_ptr<const Ip> pac, const void* data, size_t len){
                SendPkg(pac, data, len);
            };
            status->protocol = key.protocol;
            status->src = pac->getsrc();
            status->dst = pac->getdst();
            statusmap.Add(nextId(), key, status);
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
            status->packet_hdr = new Block(rbuff.data(), status->packet_hdr_len);
        }
        status->PkgProc(pac, {std::move(rbuff), len});
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
#if __linux__
    if(enable_offload) {
        debugString(pac, len - pac->gethdrlen() - sizeof(virtio_net_hdr_v1));
        pcap_write(pcap, (uchar*)data + sizeof(virtio_net_hdr_v1), len - sizeof(virtio_net_hdr_v1));
    }else{
#else
    {
#endif
        debugString(pac, len - pac->gethdrlen());
        pcap_write(pcap, data, len);
    }
    if(write(getFd(), data, len) < 0) {
        LOGE("tunio: write error: %s\n", strerror(errno));
    }
}

void TunRWer::Send(Buffer&& bb) {
    if(!statusmap.Has(bb.id)){
        return;
    }
    auto status = GetStatus(bb.id);
    if(bb.len == 0) {
        status->flags |= TUN_SEND_EOF;
    }
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
    LOGD(DVPN, "tunio: delete id: 0x%" PRIx64" (%s -> %s), due to err: %d\n",
         id, getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(), (int)code);
    resetHanlder(id, code);
    Clean(id);
}

size_t TunRWer::DataProc(std::shared_ptr<const Ip> pac, Buffer&& bb) {
    if(!statusmap.Has(VpnKey(pac))){
        return 0;
    }
    bb.id = GetId(pac);
    return readCB(std::move(bb));
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
        LOGD(DVPN, "tunio: delete id: 0x%" PRIx64" (%s -> %s), due to block\n",
             id, getRdnsWithPort(status->src).c_str(), getRdnsWithPort(status->dst).c_str());
        if(status->protocol == Protocol::TCP) {
            SendRst(std::static_pointer_cast<TcpStatus>(status));
        } else if((status->flags & TUN_SEND_EOF) == 0){
            status->UnReach(IP_ADDR_UNREACH);
        }
        Clean(id);
        break;
    case TUN_MSG_UNREACH:
        LOGD(DVPN, "tunio: delete id: 0x%" PRIx64" (%s -> %s), due to unreach\n",
             id, getRdnsWithPort(status->src).c_str(), getRdnsWithPort(status->dst).c_str());
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
