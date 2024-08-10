#include "fdns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"
#include "misc/config.h"

#include <inttypes.h>

#define IN_IS_ADDR_LOOPBACK(a)      ((((long int) (ntohl((a)->s_addr))) & 0xff000000) == 0x7f000000)


static FDns* fdns = nullptr;
static Index2<uint32_t, std::string, void*> fdns_records;
static in_addr_t fake_ip = ntohl(inet_addr(VPNADDR));


static in_addr getInet(const std::string& hostname) {
    if(hostname.find_first_of('.') == std::string::npos){
        return  in_addr{inet_addr(VPNADDR)};
    }else if(!fdns_records.Has(hostname)){
        fake_ip++;
        fdns_records.Add(fake_ip, hostname, nullptr);
    }
    return in_addr{htonl(fdns_records.GetOne(hostname)->first.first)};
}

static in6_addr getInet6(const std::string& hostname) {
    return mapIpv4(getInet(hostname), NAT64PREFIX);
}

static uint32_t getFip(const sockaddr_storage* addr){
    uint32_t fip = 0;
    switch(addr->ss_family){
        case AF_INET:
            fip = ntohl(((sockaddr_in*)addr)->sin_addr.s_addr);
            break;
        case AF_INET6:
            fip = ntohl(getMapped(((sockaddr_in6*)addr)->sin6_addr, NAT64PREFIX).s_addr);
            break;
        default:
            abort();
    }
    return fip;
}
std::string getRdns(const sockaddr_storage& addr) {
    auto fip = getFip(&addr);
    auto record = fdns_records.GetOne(fip);
    if(record != fdns_records.data().end()){
        return record->first.second;
    }else if(fip > fake_ip && fip < ntohl(inet_addr(VPNEND))) {
        //this is a fake ip, but we has no record, just block it.
        return "fake_ip";
    }else if(fip == ntohl(inet_addr(VPNADDR))){
        return "VPN";
    }else {
        return getaddrstring(&addr);
    }
}

std::string getRdnsWithPort(const sockaddr_storage& addr) {
    uint16_t port = ntohs(((const sockaddr_in*)&addr)->sin_port);
    return getRdns(addr) + ":" + std::to_string(port);
}

FDns::FDns() {
    rwer = std::make_shared<NullRWer>();
}

FDns::~FDns() {
    if(fdns == this){
        fdns = nullptr;
    }
}

FDns *FDns::GetInstance() {
    if(fdns == nullptr){
        fdns = new FDns;
    }
    return fdns;
}

#if 0
void FDns::request(std::shared_ptr<HttpReq> req, Requester*){
    auto res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
    auto reqid = req->header->request_id;
    statusmap[reqid] = FDnsStatus{
            .req = req,
            .res = res,
            .quemap = {},
    };
    req->response(res);
    req->attach([this, reqid](ChannelMessage& msg){
        FDnsStatus& status = statusmap.at(reqid);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DDNS, "<FDNS> ignore header for req: %" PRIu32"\n", msg.header->request_id);
            return 1;
        case ChannelMessage::CHANNEL_MSG_DATA:
            msg.data.id = reqid;
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            status.req->detach();
            statusmap.erase(reqid);
            return 0;
        }
        return 0;
    }, []{return 512;});
}
#endif

#if ! __LP64__
struct __uint128_t {
    uint64_t hi;
    uint64_t lo;
};
#endif

void FDns::query(uint64_t id, std::shared_ptr<MemRWer> rwer) {
    statusmap[id] = FDnsStatus{
        .rwer = rwer,
        .quemap = {},
    };
    rwer->SetReadCB([this](Buffer&& bb) -> size_t{
        LOGD(DDNS, "fdns read [%" PRIu64"], size:%zd, refs: %zd\n", bb.id, bb.len, bb.refs());
        if(bb.len == 0){
            statusmap.erase(bb.id);
        } else {
            Recv(std::move(bb));
        }
        return bb.len;
    });
    rwer->SetErrorCB([this, id](int, int) {
        statusmap.erase(id);
    });
}

void FDns::Recv(Buffer&& bb) {
    FDnsStatus& status = statusmap.at(bb.id);
    uint64_t id = bb.id;
    auto que = std::make_shared<Dns_Query>((const char *)bb.data(), bb.len);
    if(!que->valid){
        LOGD(DDNS, "invalid dns request [%" PRIu64"], len: %zd\n", id, bb.len);
        return;
    }
    if(status.quemap.count(que->id)) {
        LOG("<FDNS> [%" PRIu64"] Drop dup query %s, id:%d, type:%d\n", id, que->domain, que->id, que->type);
        return;
    }
    LOG("<FDNS> [%" PRIu64"] Query %s, id:%d, type:%d\n", id, que->domain, que->id, que->type);
#if __LP64__
    __uint128_t index = (__uint128_t)id << 64 | que->id;
#else
    __uint128_t index{id , que->id};
#endif
    Dns_Result* result = nullptr;
    if(que->type == 12){
        auto record = fdns_records.GetOne(getFip(&que->ptr_addr));
        if(record != fdns_records.data().end()){
            result = new Dns_Result(record->first.second.c_str());
        }
    }else if(que->type == 1 || que->type == 28) {
        if(que->type == 28 && !opt.ipv6_enabled) {
            //return empty response for ipv6
            result = new Dns_Result(que->domain);
        } else {
            strategy stra = getstrategy(que->domain);
            if (stra.s == Strategy::direct) {
                status.quemap.emplace(que->id, que);
                return query_host(que->domain, DnsCb, std::make_shared<__uint128_t>(index));
            } else if (que->domain[0] == 0) {
                //return empty response for root domain
                result = new Dns_Result(que->domain);
            } else if (que->type == 1) {
                in_addr addr = getInet(que->domain);
                result = new Dns_Result(que->domain, &addr);
            } else if (que->type == 28) {
                in6_addr addr = getInet6(que->domain);
                result = new Dns_Result(que->domain, &addr);
            }
        }
    }
    if(result == nullptr) {
        status.quemap.emplace(que->id, que);
        return query_dns(que->domain, que->type, RawCb, std::make_shared<__uint128_t>(index));
    }
    Buffer buff{BUF_LEN, bb.id};
    buff.truncate(result->build(que.get(), (uchar*)buff.mutable_data()));
    status.rwer->Send(std::move(buff));
    delete result;
}

static bool isLoopBack(const sockaddr_storage* addr) {
    if(addr->ss_family == AF_INET) {
        const sockaddr_in* addr4 = (const sockaddr_in*)addr;
        return IN_IS_ADDR_LOOPBACK(&addr4->sin_addr);
    }else if(addr->ss_family == AF_INET6) {
        const sockaddr_in6* addr6 = (const sockaddr_in6*)addr;
        return IN6_IS_ADDR_LOOPBACK(&addr6->sin6_addr);
    }
    return false;
}

void FDns::DnsCb(std::shared_ptr<void> param, int error, const std::list<sockaddr_storage>& addrs) {
    auto index = *std::static_pointer_cast<__uint128_t>(param);
#if __LP64__
    uint64_t id = index >> 64;
#else
    uint64_t id = index.hi;
#endif
    if(fdns->statusmap.count(id) == 0){
        return;
    }
    FDnsStatus& status = fdns->statusmap.at(id);
#if __LP64__
    uint16_t qid = index & 0xffff;
#else
    uint16_t qid = index.lo & 0xffff;
#endif
    std::shared_ptr<Dns_Query> que = status.quemap.at(qid);
    assert(que->id == qid);
    LOGD(DDNS, "fdns cb [%" PRIu64"] %s, id:%d, size:%zd, error: %d\n",
         id, que->domain, que->id, addrs.size(), error);
    Dns_Result* result = new Dns_Result(que->domain);
    Buffer buff{BUF_LEN, id};
    if(error) {
        buff.truncate(Dns_Result::buildError(que.get(), error, (uchar*)buff.mutable_data()));
        status.rwer->Send(std::move(buff));
    } else {
        for(const auto& addr : addrs) {
            if(isLoopBack(&addr)) {
                result->addrs.emplace_back(addr);
            }
        }
        if(result->addrs.size() != addrs.size()) {
            sockaddr_storage ip;
            memset(&ip, 0, sizeof(ip));
            if (que->type == 1) {
                sockaddr_in* ip4 = (sockaddr_in*)&ip;
                ip4->sin_family = AF_INET;
                ip4->sin_addr = getInet(que->domain);
            }
            if (que->type == 28) {
                sockaddr_in6* ip6 = (sockaddr_in6*)&ip;
                ip6->sin6_family = AF_INET6;
                ip6->sin6_addr = getInet6(que->domain);
            }
            result->addrs.push_back(ip);
        }
        buff.truncate(result->build(que.get(), (uchar*)buff.mutable_data()));
        status.rwer->Send(std::move(buff));
    }
    status.quemap.erase(que->id);
    delete result;
}

void FDns::RawCb(std::shared_ptr<void> param, const char* data, size_t size) {
    auto index = *std::static_pointer_cast<__uint128_t>(param);
#if __LP64__
    uint64_t id = index >> 64;
#else
    uint64_t id = index.hi;
#endif
    if(fdns->statusmap.count(id) == 0){
        return;
    }
    LOGD(DDNS, "fdns rawcb [%" PRIu64"], size:%zd\n", id, size);
    FDnsStatus& status = fdns->statusmap[id];
#if __LP64__
    uint16_t qid = index & 0xffff;
#else
    uint16_t qid = index.lo & 0xffff;
#endif
    std::shared_ptr<Dns_Query> que = status.quemap.at(qid);
    assert(que->id == qid);
    Buffer buff{BUF_LEN, id};
    if(data){
        LOGD(DDNS, "<FDNS> Query raw response [%d]\n", que->id);
        memcpy(buff.mutable_data(), data, size);
        DNS_HDR *dnshdr = (DNS_HDR*)buff.mutable_data();
        dnshdr->id = htons(que->id);
        buff.truncate(size);
        status.rwer->Send(std::move(buff));
    }else {
        LOGD(DDNS, "<FDNS> Query raw response [%d] error\n", que->id);
        Dns_Result rr(que->domain);
        buff.truncate(Dns_Result::buildError(que.get(), DNS_SERVER_FAIL, (unsigned char*)buff.mutable_data()));
        status.rwer->Send(std::move(buff));
    }
    status.quemap.erase(que->id);
}

void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns: %p, size: %zu\n", this, statusmap.size());
    for(const auto& i : statusmap) {
        const FDnsStatus& status = i.second;
        dp(param, "  [%" PRIu64 "]: %s\n", i.first, dumpDest(status.rwer->getSrc()).c_str());
        for(const auto& p : status.quemap) {
            auto que = p.second;
            dp(param, "    %s, id=%d, type=%d\n", que->domain, que->id, que->type);
        }
    }
}

void FDns::dump_usage(Dumper dp, void *param) {
    size_t usage = 0;
    for(const auto& i : statusmap) {
        usage += sizeof(i.first) + sizeof(i.second) + i.second.rwer->mem_usage();
        const FDnsStatus& status = i.second;
        usage += status.quemap.size() * (sizeof(uint16_t) + sizeof(Dns_Query));
    }
    dp(param, "FDns %p: %zd, reqmap: %zd\n", this, sizeof(*this), usage);
}
