#include "common/common.h"
#include "tunio.h"
#include "misc/pcap.h"
#include "misc/config.h"
#include "misc/util.h"
#include "res/fdns.h"

#include <errno.h>

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

char VpnKey::version() const {
    if(dst.ss_family == AF_INET){
        return 4;
    }
    if(dst.ss_family == AF_INET6){
        return 6;
    }
    abort();
    return 0;
}


static bool operator<(sockaddr_storage a, sockaddr_storage b) {
    return memcmp(&a, &b, sizeof(sockaddr_storage)) < 0;
}

bool operator<(VpnKey a, VpnKey b) {
    return std::tie(a.protocol, a.src, a.dst) < std::tie(b.protocol, b.src, b.dst);
}

#define ICMP_PING(type) ((type) == ICMP_ECHO || (type) == ICMP_ECHOREPLY)
#define ICMP6_PING(type)  ((type) == ICMP6_ECHO_REQUEST || (type) == ICMP6_ECHO_REPLY)

void debugString(std::shared_ptr<const Ip> pac, size_t len) {
    switch(pac->gettype()){
    case IPPROTO_TCP:
        LOGD(DVPN, "<tcp> (%s -> %s) (%u - %u) flag: %s size:%zu\n",
            getRdns(pac->getsrc()).c_str(), getRdns(pac->getdst()).c_str(),
            pac->tcp->getseq(), pac->tcp->getack(), pac->tcp->getflags(), len);
        return;
    case IPPROTO_UDP:
        LOGD(DVPN, "<udp> (%s -> %s) size:%zu\n",
            getRdns(pac->getsrc()).c_str(), getRdns(pac->getdst()).c_str(), len);
        return;
    case IPPROTO_ICMP:
        if(ICMP_PING(pac->icmp->gettype())){
            LOGD(DVPN, "<ping> (%s -> %s) (%u) size:%zu\n",
                getRdns(pac->getsrc()).c_str(), getRdns(pac->getdst()).c_str(),
                pac->icmp->getseq(), len);
            return;
        }
        break;
    case IPPROTO_ICMPV6:
        if(ICMP6_PING(pac->icmp6->gettype())) {
            LOGD(DVPN, "<ping6> (%s -> %s) (%u) size:%zu\n",
                getRdns(pac->getsrc()).c_str(), getRdns(pac->getdst()).c_str(),
                pac->icmp6->getseq(), len);
            return;
        }
        break;
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
                     protstr(key.protocol), getRdns(key.src).c_str(), getRdns(key.dst).c_str());
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
                     protstr(key.protocol), getRdns(key.src).c_str(), getRdns(key.dst).c_str());
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
                TcpStatus* tstatus = new TcpStatus();
                tstatus->InProc = reinterpret_cast<InProc_t>(&TcpHE::SynProc);
                tstatus->Write = reinterpret_cast<Write_t>(&TcpHE::SendData);
                tstatus->Unreach = reinterpret_cast<Unreach_t>(&TcpHE::Unreach);
                tstatus->Cap = reinterpret_cast<Cap_t>(&TcpHE::Cap);
                status = std::shared_ptr<IpStatus>(tstatus);
                break;
            }
            case Protocol::UDP:{
                UdpStatus* ustatus = new UdpStatus();
                ustatus->InProc = reinterpret_cast<InProc_t>(&UdpHE::DefaultProc);
                ustatus->Write = reinterpret_cast<Write_t>(&UdpHE::SendData);
                ustatus->Unreach = reinterpret_cast<Unreach_t>(&UdpHE::Unreach);
                ustatus->Cap = reinterpret_cast<Cap_t>(&UdpHE::Cap);
                status = std::shared_ptr<IpStatus>(ustatus);
                break;
            }
            case Protocol::ICMP:{
                IcmpStatus* istatus = new IcmpStatus();
                istatus->InProc = reinterpret_cast<InProc_t>(&IcmpHE::DefaultProc);
                istatus->Write = reinterpret_cast<Write_t>(&IcmpHE::SendData);
                istatus->Unreach = reinterpret_cast<Unreach_t>(&IcmpHE::Unreach);
                istatus->Cap = reinterpret_cast<Cap_t>(&IcmpHE::Cap);
                status = std::shared_ptr<IpStatus>(istatus);
                break;
            }
            case Protocol::NONE:
                LOGD(DVPN, "ignore unknow protocol: %d\n", pac->gettype());
                continue;
            default:
                continue;
            }
            status->protocol = key.protocol;
            status->src = pac->getsrc();
            status->dst = pac->getdst();
            statusmap.Add(next_id++, key, status);
        }else{
            if(transIcmp){
                uint64_t id = statusmap.GetOne(key)->first.first;
                resetHanlder(id, ICMP_UNREACH_ERR);
                statusmap.Delete(id);
                continue;
            }
            status = statusmap.GetOne(key)->second;
        }
        if(status->packet_hdr == nullptr){
            status->packet_hdr_len = pac->gethdrlen();
            status->packet_hdr = std::make_shared<Block>(rbuff, status->packet_hdr_len);
        }
        (this->*status->InProc)(status, pac, rbuff, len);
    }
}

ssize_t TunRWer::Write(const void*, size_t, uint64_t) {
    errno = EINVAL;
    return -1;
}

void TunRWer::sendPkg(std::shared_ptr<Ip> pac, Buffer&& bb) {
    debugString(pac, bb.len);
    pac->build_packet(bb);
    pcap_write_with_generated_ethhdr(pcap, bb.data(), bb.len);
    write(getFd(), bb.data(), bb.len);
}

buff_iterator TunRWer::buffer_insert(buff_iterator where, Buffer&& bb) {
    auto status = GetStatus(bb.id);
    (this->*status->Write)(status, std::move(bb));
    return where;
}

void TunRWer::ReqProc(std::shared_ptr<const Ip> pac) {
    if(reqProc){
        reqProc(GetId(pac), pac);
    }
}

void TunRWer::ErrProc(std::shared_ptr<const Ip> pac, uint32_t code) {
    uint64_t id = GetId(pac);
    resetHanlder(id, code);
    statusmap.Delete(id);
}

bool TunRWer::DataProc(std::shared_ptr<const Ip> pac, const void* data, size_t len) {
    return readCB(GetId(pac), data, len) == 0;
}

void TunRWer::TcpAckProc(std::shared_ptr<const Ip> pac) {
    return writeCB(GetId(pac));
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
        if(status->protocol == Protocol::TCP) {
            SendRst(std::static_pointer_cast<TcpStatus>(status));
            statusmap.Delete(id);
        } else {
            (this->*status->Unreach)(status, IP_ADDR_UNREACH);
            //这里必须要延后清理，是因为新请求可能会被立即阻断，但是这个请求的body还没有被处理，
            //还会继续调用DataProc，而不想在那边再去判断这种情况
            addjob([&]{statusmap.Delete(id);}, 0, JOB_FLAGS_AUTORELEASE);
        }
        break;
    case TUN_MSG_UNREACH:
        (this->*status->Unreach)(status, IP_PORT_UNREACH);
        addjob([&]{statusmap.Delete(id);}, 0, JOB_FLAGS_AUTORELEASE);
        break;
    }
}

void TunRWer::setResetHandler(std::function<void (uint64_t, uint32_t)> func) {
    resetHanlder = std::move(func);
}

ssize_t TunRWer::cap(uint64_t id) {
    auto status = GetStatus(id);
    return (this->*status->Cap)(status);
}

bool TunRWer::idle(uint64_t id) {
    return !statusmap.Has(id);
}

void TunRWer::dump_status(Dumper dp, void *param) {
    dp(param, "TunRwer: %p\n", this);
    for(const auto& status : statusmap.data()) {
        const auto& key = status.first.second;
        dp(param, "  0x%lx: <%s> %s -> %s\n", status.first.first,
           protstr(key.protocol),
           std::string(storage_ntoa(&key.src)).c_str(),
           std::string(storage_ntoa(&key.dst)).c_str());
    }
}