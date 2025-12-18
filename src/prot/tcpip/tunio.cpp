#include "common/common.h"
#include "tunio.h"
#include "icmp.h"
#include "tcp.h"
#include "udp.h"
#include "misc/pcap.h"
#include "misc/config.h"
#include "misc/util.h"
#include "misc/defer.h"
#include "misc/net.h"
#include "res/fdns.h"

#include <errno.h>
#include <inttypes.h>

#include <algorithm>
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

static bool operator<(const VpnKey& a, const VpnKey& b) {
    return std::tie(a.protocol, a.src, a.dst) < std::tie(b.protocol, b.src, b.dst);
}

#define ICMP_PING(type) ((type) == ICMP_ECHO || (type) == ICMP_ECHOREPLY)
#define ICMP6_PING(type)  ((type) == ICMP6_ECHO_REQUEST || (type) == ICMP6_ECHO_REPLY)

static void debugString(std::shared_ptr<const Ip> pac, size_t len, bool reverse) {
    switch(pac->gettype()){
    case IPPROTO_TCP:
        if(reverse) {
            LOGD(DVPN, "<tcp> (%s <- %s) (%u - %u) flag: %s size:%zu\n",
                getRdnsWithPort(pac->getdst()).c_str(), getRdnsWithPort(pac->getsrc()).c_str(),
                pac->tcp->getseq(), pac->tcp->getack(), pac->tcp->getflags(), len);
        } else {
            LOGD(DVPN, "<tcp> (%s -> %s) (%u - %u) flag: %s size:%zu\n",
                getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                pac->tcp->getseq(), pac->tcp->getack(), pac->tcp->getflags(), len);
        }
        return;
    case IPPROTO_UDP:
        if(reverse) {
            LOGD(DVPN, "<udp> (%s <- %s) size:%zu\n",
                getRdnsWithPort(pac->getdst()).c_str(), getRdnsWithPort(pac->getsrc()).c_str(), len);
        } else {
            LOGD(DVPN, "<udp> (%s -> %s) size:%zu\n",
                getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(), len);
        }
        return;
    case IPPROTO_ICMP:
        if(reverse) {
            LOGD(DVPN, "<%s> (%s <- %s) (%u) size:%zu\n",
                ICMP_PING(pac->icmp->gettype())?"ping":"icmp",
                getRdnsWithPort(pac->getdst()).c_str(), getRdnsWithPort(pac->getsrc()).c_str(),
                pac->icmp->getseq(), len);
        } else {
            LOGD(DVPN, "<%s> (%s -> %s) (%u) size:%zu\n",
                ICMP_PING(pac->icmp->gettype())?"ping":"icmp",
                getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                pac->icmp->getseq(), len);
        }
        return;
    case IPPROTO_ICMPV6:
        if(reverse) {
            LOGD(DVPN, "<%s> (%s -> %s) (%u) size:%zu\n",
                ICMP6_PING(pac->icmp6->gettype())?"ping6":"icmp6",
                getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                pac->icmp6->getseq(), len);
        } else {
            LOGD(DVPN, "<%s> (%s -> %s) (%u) size:%zu\n",
                ICMP6_PING(pac->icmp6->gettype())?"ping6":"icmp6",
                getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(),
                pac->icmp6->getseq(), len);
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

TunRWer::TunRWer(int fd, bool enable_offload, std::shared_ptr<IRWerCallback> cb):
    RWer(fd, std::move(cb)), enable_offload(enable_offload)
{
    stats = RWerStats::Connected;
    handleEvent = (void (Ep::*)(RW_EVENT))&TunRWer::defaultHE;
    if(opt.pcap_file) {
        pcap = pcap_create(opt.pcap_file);
    }
    set_checksum_offload(enable_offload);
#ifdef HAVE_URING
    InitIoUring();
#endif
    setEvents(RW_EVENT::READ);
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
#ifdef HAVE_URING
    CleanupIoUring();
#endif
}

int TunRWer::getFd() const{
#ifdef HAVE_URING
    if(use_io_uring) {
        return ring.ring_fd;
    }
#endif
    return Ep::getFd();
}

void TunRWer::ReadData() {
#ifdef HAVE_URING
    if (use_io_uring) {
        HandleIoUringCompletion();
        return;
    }
#endif
    while(true) {
        Block rbuff(TUN_BUF_LEN);
        int ret = read(Ep::getFd(), rbuff.data(), TUN_BUF_LEN);
        LOGD(DVPN, "read %d bytes from tun\n", ret);
        if(ret <= 0) {
            if(errno == EAGAIN) return;
            ErrorHE(SOCKET_ERR, errno);
            return;
        }
        ProcessPacket(Buffer{std::move(rbuff), (size_t)ret});
    }
}

void TunRWer::ProcessPacket(Buffer&& bb){
#if __linux__
    if(bb.len <= (int)sizeof(virtio_net_hdr_v1)) {
        return;
    }
    if(enable_offload) {
        auto hdr = (const virtio_net_hdr_v1*)bb.data();
        if(hdr->gso_type != VIRTIO_NET_HDR_GSO_NONE) {
            LOGD(DVPN, "gso type: %d, gso size: %d, num: %d\n", hdr->gso_type, hdr->gso_size, hdr->num_buffers);
        }
        bb.reserve(sizeof(virtio_net_hdr_v1));
    }
#endif
    pcap_write(pcap, bb.data(), bb.len);
    auto pac = MakeIp(bb.data(), bb.len);
    if(pac == nullptr){
        return;
    }
    debugString(pac, bb.len - pac->gethdrlen(), false);
    VpnKey key(pac);

    bool transIcmp = false;
    bool tooBig = false;
    uint32_t icmpMtu = 0;
    std::shared_ptr<const Ip> icmpPayload;
    if(pac->gettype() == IPPROTO_ICMP) {
        uint16_t type = pac->icmp->gettype();
        if(type ==  ICMP_UNREACH) {
            icmpPayload = MakeIp((const char*)bb.data() + pac->gethdrlen(), bb.len-pac->gethdrlen());
            if(icmpPayload == nullptr){
                return;
            }
            uint8_t code = pac->icmp->getcode();
#ifdef ICMP_UNREACH_NEEDFRAG
            if(code == ICMP_UNREACH_NEEDFRAG) {
#elif defined(ICMP_FRAG_NEEDED)
            if(code == ICMP_FRAG_NEEDED) {
#else
            if(code == 4) {
#endif
                tooBig = true;
                icmpMtu = pac->icmp->getmtu();
            } else {
                transIcmp = true;
            }
            key = VpnKey(icmpPayload).reverse();
            LOGD(DVPN, "get icmp unreach for: <%s> %s - %s\n",
                    protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
        }else if(!ICMP_PING(type)) {
            LOGD(DVPN, "ignore icmp type: %d\n", type);
            return;
        }
    }else if(pac->gettype() == IPPROTO_ICMPV6) {
        uint16_t type = pac->icmp6->gettype();
        if(type == ICMP6_DST_UNREACH){
            icmpPayload = MakeIp((const char*)bb.data() + pac->gethdrlen(), bb.len-pac->gethdrlen());
            if(icmpPayload == nullptr){
                return;
            }
            transIcmp = true;
            key = VpnKey(icmpPayload).reverse();
            LOGD(DVPN, "get icmp6 unreach for: <%s> %s - %s\n",
                    protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
        }else if(type == ICMP6_PACKET_TOO_BIG){
            icmpPayload = MakeIp((const char*)bb.data() + pac->gethdrlen(), bb.len-pac->gethdrlen());
            if(icmpPayload == nullptr){
                return;
            }
            tooBig = true;
            icmpMtu = pac->icmp6->getmtu();
            key = VpnKey(icmpPayload).reverse();
            LOGD(DVPN, "get icmp6 too big for: <%s> %s - %s\n",
                    protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
        }else if(!ICMP6_PING(type)) {
            LOGD(DVPN, "ignore icmp6 type: %d\n", type);
            return;
        }
    }
    std::shared_ptr<IpStatus> status;
    if(!statusmap.Has(key)){
        if(transIcmp || tooBig) {
            return;
        }
        if(pac->getdport() == 0 || pac->getsport() == 0) {
            LOG("<tunio> ignore invalid port: <%s> %s -> %s\n",
                protstr(key.protocol), getRdnsWithPort(key.src).c_str(), getRdnsWithPort(key.dst).c_str());
            return;
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
            return;
        default:
            return;
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
        status->sendCB = [this](std::shared_ptr<const Ip> pac, Buffer&& bb){
            SendPkg(pac, std::move(bb));
        };
        status->protocol = key.protocol;
        status->src = pac->getsrc();
        status->dst = pac->getdst();
        statusmap.Add(nextId(), key, status);
    }else{
        if(transIcmp){
            uint64_t id = statusmap.GetOne(key)->first.first;
            if(auto cb = std::dynamic_pointer_cast<ITunCallback>(callback.lock()); cb){
                cb->resetHanlder(id, ICMP_UNREACH_ERR);
            }
            Clean(id);
            return;
        }
        if(tooBig){
            status = statusmap.GetOne(key)->second;
            if(!icmpPayload || icmpPayload->gettype() != IPPROTO_TCP) {
                return;
            }
            if(icmpMtu == 0) {
                LOGD(DVPN, "icmp too big without mtu, ignore\n");
                return;
            }
            size_t hdr_len = icmpPayload->gethdrlen();
            if(icmpMtu <= hdr_len) {
                LOGD(DVPN, "icmp too big invalid mtu: %u <= %zu\n", icmpMtu, hdr_len);
                return;
            }
            uint32_t new_mss = std::min<uint32_t>(icmpMtu - hdr_len, UINT16_MAX);
            UpdateTcpMss(status, static_cast<uint16_t>(new_mss));
            return;
        }
        status = statusmap.GetOne(key)->second;
    }
    if(status->packet_hdr.empty()){
        status->packet_hdr.append((const char*)bb.data(), pac->gethdrlen());
    }
    status->PkgProc(pac, std::move(bb));
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

void TunRWer::SendPkg(std::shared_ptr<const Ip> pac, Buffer&& bb) {
    const void* data = bb.data();
    size_t len = bb.len;

#if __linux__
    if(enable_offload) {
        debugString(pac, len - pac->gethdrlen() - sizeof(virtio_net_hdr_v1), true);
        pcap_write(pcap, (uchar*)data + sizeof(virtio_net_hdr_v1), len - sizeof(virtio_net_hdr_v1));
    }else{
#else
    {
#endif
        debugString(pac, len - pac->gethdrlen(), true);
        pcap_write(pcap, data, len);
    }

#ifdef HAVE_URING
    if (use_io_uring) {
        struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) {
            LOGD(DVPN, "Failed to get SQE for write operation, queue full\n");
            return;
        }

        io_uring_prep_write(sqe, Ep::getFd(), data, bb.len, 0);
        sqe->user_data = (uint64_t)data;
        write_buffer.emplace((uint64_t)data, std::move(bb));
        if(io_uring_sq_space_left(&ring) <= 64) {
            int ret = io_uring_submit(&ring);
            if(ret < 0) {
                LOGE("io_uring_submit failed: %s\n", strerror(-ret));
            }
        }else {
            submitter = updatejob_with_name(std::move(submitter), [this]{
                int ret = io_uring_submit(&ring);
                if(ret < 0) {
                    LOGE("io_uring_submit failed: %s\n", strerror(-ret));
                }
            }, "io_uring_submit", 0);
        }
        return;
    }
#endif

    if(write(Ep::getFd(), data, len) < 0) {
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
    if(auto cb = std::dynamic_pointer_cast<ITunCallback>(callback.lock()); cb) {
        cb->reqProc(GetId(pac), pac);
    }
}

void TunRWer::Clean(uint64_t id) {
    auto status = GetStatus(id);
    status->PkgProc = nullptr;
    status->SendPkg = nullptr;
    status->UnReach = nullptr;
    status->Cap = nullptr;
    status->packet_hdr.clear();
    statusmap.Delete(id);
}

void TunRWer::ErrProc(std::shared_ptr<const Ip> pac, uint32_t code) {
    uint64_t id = GetId(pac);
    LOGD(DVPN, "tunio: delete id: 0x%" PRIx64" (%s -> %s), due to err: %d\n",
         id, getRdnsWithPort(pac->getsrc()).c_str(), getRdnsWithPort(pac->getdst()).c_str(), (int)code);
    if(auto cb = std::dynamic_pointer_cast<ITunCallback>(callback.lock()); cb) {
        cb->resetHanlder(id, code);
    }
    Clean(id);
}

size_t TunRWer::DataProc(std::shared_ptr<const Ip> pac, Buffer&& bb) {
    if(!statusmap.Has(VpnKey(pac))){
        return 0;
    }
    bb.id = GetId(pac);
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    if(auto cb = callback.lock(); cb) {
        return cb->readCB(std::move(bb));
    }
    return 0;
}

void TunRWer::AckProc(std::shared_ptr<const Ip> pac) {
    if(!statusmap.Has(VpnKey(pac))) {
        return;
    }
    auto itr = statusmap.GetOne(VpnKey(pac));
    if(auto cb = callback.lock(); cb && itr->second->Cap() >= 0) {
        return cb->writeCB(itr->first.first);
    }
}

void TunRWer::sendMsg(uint64_t id, uint32_t msg) {
    if(!statusmap.Has(id)){
        return;
    }
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

ssize_t TunRWer::cap(uint64_t id) {
    if(!statusmap.Has(id)){
        return -1;
    }
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
        dp(param, "  [%" PRIu64"]: <tcp> %s -> %s, srtt=%zd, state=%d, wlist: %zd, rlen: %zd, window: %zd\n",
           value.first.first,
           std::string(storage_ntoa(&status->src)).c_str(),
           std::string(storage_ntoa(&status->dst)).c_str(),
           (size_t) status->srtt, status->state,
           status->sent_list.size(), status->rbuf.length(),
           status->Cap());
        break;
    }
    case Protocol::UDP: {
        auto status = std::static_pointer_cast<UdpStatus>(status_);
        dp(param, "  [%" PRIu64"]: <udp> %s -> %s, rx_packets=%zd, rx_len=%zd, tx_packets=%zd, tx_len=%zd\n",
           value.first.first,
           std::string(storage_ntoa(&status->src)).c_str(),
           std::string(storage_ntoa(&status->dst)).c_str(),
           status->rx_packets, status->rx_len, status->tx_packets, status->tx_len);
        break;
    }
    case Protocol::ICMP: {
        auto status = std::static_pointer_cast<IcmpStatus>(status_);
        dp(param, "  [%" PRIu64"]: <icmp> %s -> %s, id=%d, seq=%d\n",
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
    dp(param, "TunRwer <%d>: %p, io_uring: %s session: %zd\n",
       Ep::getFd(), this, use_io_uring?"enable":"disable", statusmap.size());
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

#ifdef HAVE_URING
void TunRWer::InitIoUring() {
    if(!is_kernel_version_ge(6, 7)) {
        // io_uring_prep_read_multishot only available since 6.7
        LOG("kernel version is less than 6.7, disable io_uring\n");
        return;
    }
    int ret = io_uring_queue_init(URING_QUEUE_DEPTH, &ring, 0);
    if (ret < 0) {
        LOGD(DVPN, "io_uring init failed: %s, falling back to regular read\n", strerror(-ret));
        return;
    }
    defer([this]{
        if(use_io_uring) {
            return;
        }
        io_uring_queue_exit(&ring);
    });
    // Allocate buffer ring using liburing API
    buf_ring = io_uring_setup_buf_ring(&ring, num_buffers, PBUF_RING_ID, 0, &ret);
    if (!buf_ring || ret) {
        LOGE("Failed to allocate buffer ring: %d\n", ret);
        return;
    }
    defer([this]{
        if(use_io_uring) {
            return;
        }
        io_uring_free_buf_ring(&ring, buf_ring, num_buffers, PBUF_RING_ID);
        buf_ring = nullptr;
    });

    // Allocate memory for the actual buffers
    read_buffer = aligned_alloc(getpagesize(), MAX_BUF_LEN);
    if (!read_buffer) {
        LOGE("Failed to allocate memory for ring buffers\n");
        return;
    }
    defer([this]{
        if(use_io_uring) {
            return;
        }
        free(read_buffer);
        read_buffer = nullptr;
    });

    // Add all buffers to the ring
    for (size_t i = 0; i < num_buffers; i++) {
        void* buffer_addr = (char*)read_buffer + (i * TUN_BUF_LEN);
        io_uring_buf_ring_add(buf_ring, buffer_addr, TUN_BUF_LEN, i,
                              io_uring_buf_ring_mask(num_buffers), i);
    }
    io_uring_buf_ring_advance(buf_ring, num_buffers);

    use_io_uring = true;
    LOGD(DVPN, "io_uring with PBUF_RING initialized successfully\n");
    // Submit initial read request
    SubmitRead();
}

void TunRWer::CleanupIoUring() {
    if (!use_io_uring) {
        return;
    }

    submitter = nullptr;
    if (buf_ring) {
        io_uring_free_buf_ring(&ring, buf_ring, num_buffers, PBUF_RING_ID);
        buf_ring = nullptr;
    }
    if (read_buffer) {
        free(read_buffer);
        read_buffer = nullptr;
    }
    // Clean up any pending writes
    write_buffer.clear();

    io_uring_queue_exit(&ring);
    use_io_uring = false;
}

void TunRWer::SubmitRead() {
    struct io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    if (!sqe) {
        LOGE("Failed to get SQE for read operation\n");
        return;
    }

    // Try recv_multishot first, fallback to read if needed
    io_uring_prep_read_multishot(sqe, Ep::getFd(), 0, 0, PBUF_RING_ID);
    sqe->user_data = 0;
    submitter = updatejob_with_name(std::move(submitter), [this]{
        int ret = io_uring_submit(&ring);
        if(ret < 0) {
            LOGE("io_uring_submit failed: %s\n", strerror(-ret));
        }
    }, "io_uring_submit", 0);
    LOGD(DVPN, "Multishot read prepared successfully\n");
}

void TunRWer::HandleIoUringCompletion() {
    struct io_uring_cqe* cqe;
    unsigned head;
    unsigned cqe_count = 0;
    bool shouldReArm = false;

    io_uring_for_each_cqe(&ring, head, cqe) {
        cqe_count++;

        if (cqe->user_data == 0) {
            // Read completion
            if (cqe->res > 0) {
                // Successful read
                int len = cqe->res;
                int buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                LOGD(DVPN, "io_uring read %d bytes from tun, buffer id: %d\n", len, buf_id);

                // Calculate buffer address from ring buffer and buffer id
                void* buffer_addr = (char*)read_buffer + (buf_id * TUN_BUF_LEN);
                ProcessPacket(Buffer{(const char*)buffer_addr, (size_t)len});

                // Return the buffer to the ring
                io_uring_buf_ring_add(buf_ring, buffer_addr, TUN_BUF_LEN, buf_id,
                                      io_uring_buf_ring_mask(num_buffers), 0);
                io_uring_buf_ring_advance(buf_ring, 1);
            } else {
                // Read error or EOF
                LOGD(DVPN, "io_uring read return error: %d\n", cqe->res);
                if(-cqe->res == ENOBUFS) {
                    LOGD(DVPN, "io_uring no buf, restarting\n");
                    shouldReArm = true;
                } else  {
                    LOGE("io_uring read error: %d\n", cqe->res);
                    ErrorHE(SOCKET_ERR, -cqe->res);
                    return;
                }
            }

            // Check if multishot has ended (no MORE flag)
            if (!(cqe->flags & IORING_CQE_F_MORE)) {
                LOGD(DVPN, "io_uring ended, restarting\n");
                shouldReArm = true;
            }
        } else {
            // Write completion (user_data == ptr)
            if (cqe->res > 0) {
                LOGD(DVPN, "io_uring wrote %d bytes to tun\n", cqe->res);
            } else {
                LOGE("io_uring write error: %d\n", cqe->res);
            }
            write_buffer.erase(cqe->user_data);
        }
    }
    io_uring_cq_advance(&ring, cqe_count);
    if(shouldReArm) {
        SubmitRead();
    }
}

#endif
