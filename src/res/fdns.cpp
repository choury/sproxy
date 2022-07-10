#include "fdns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"
#include "misc/config.h"

#include <inttypes.h>

static FDns* fdns = nullptr;
static Index2<uint32_t, std::string, void*> fdns_records;
static in_addr_t fake_ip = ntohl(inet_addr(VPNADDR));


static in_addr getInet(const std::string& hostname) {
    in_addr addr{};

    if(hostname.find_first_of('.') == std::string::npos){
        addr.s_addr = inet_addr(VPNADDR);
    }else if(fdns_records.Has(hostname)){
        addr.s_addr = htonl(fdns_records.GetOne(hostname)->first.first);
    }else{
        fake_ip++;
        addr.s_addr= htonl(fake_ip);
        fdns_records.Add(fake_ip, hostname, nullptr);
    }
    return addr;
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
    std::string host;
    auto fip = getFip(&addr);
    auto record = fdns_records.GetOne(fip);
    if(record != fdns_records.data().end()){
        host = record->first.second;
    }else if(fip > fake_ip && fip < ntohl(inet_addr(VPNEND))) {
        //this is a fake ip, but we has no record, just block it.
        host = "fake_ip";
    }else if(fip == ntohl(inet_addr(VPNADDR))){
        host = "VPN";
    }else {
        return storage_ntoa(&addr);
    }
    uint16_t port = ntohs(((const sockaddr_in*)&addr)->sin_port);
    return host + ":" + std::to_string(port);
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

void FDns::request(std::shared_ptr<HttpReq> req, Requester*){
    auto res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
    auto id = req->header->request_id;
    statusmap[id] = FDnsStatus{
            .req = req,
            .res = res,
            .que = nullptr,
    };
    req->response(res);
    req->attach([this, id](ChannelMessage& msg){
        FDnsStatus& status = statusmap.at(id);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DDNS, "<FDNS> ignore header for req\n");
            return 1;
        case ChannelMessage::CHANNEL_MSG_DATA:
            msg.data.id = id;
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            status.req->detach();
            statusmap.erase(id);
            return 0;
        }
        return 0;
    }, []{return 512;});
}

void FDns::Recv(Buffer&& bb) {
    FDnsStatus& status = statusmap.at(bb.id);
    auto que = std::make_shared<Dns_Query>((const char *)bb.data(), bb.len);
    if(!que->valid){
        LOGE("invalid dns request [%zd]\n", bb.len);
        status.res->send(nullptr);
        return;
    }
    status.que = que;
    LOG("[FDNS] Query %s: %d\n", que->domain, que->type);
    Dns_Result* result = nullptr;
    if(que->type == 12){
        auto record = fdns_records.GetOne(getFip(&que->ptr_addr));
        if(record != fdns_records.data().end()){
            result = new Dns_Result(record->first.second.c_str());
        }
    }else if(que->type == 1 || que->type == 28) {
        strategy stra = getstrategy(que->domain);
        if (stra.s == Strategy::direct) {
            return query_host(que->domain, DnsCb, std::make_shared<uint64_t>(bb.id));
        }
        if(que->domain[0] == 0){
            //return empty response for root domain
            result = new Dns_Result(que->domain);
        }else if(que->type == 1){
            in_addr addr = getInet(que->domain);
            result = new Dns_Result(que->domain, &addr);
        }else if(opt.ipv6_enabled) {
            in6_addr addr = getInet6(que->domain);
            result = new Dns_Result(que->domain, &addr);
        }else{
            result = new Dns_Result(que->domain);
        }
    }
    if(result == nullptr) {
        return query_dns(que->domain, que->type, RawCb, std::make_shared<uint64_t>(bb.id));
    }
    auto buff = std::make_shared<Block>(BUF_LEN);
    status.res->send({buff, (size_t)result->build(que.get(), (uchar*)buff->data())});
    status.res->send(nullptr);
}

void FDns::DnsCb(std::shared_ptr<void> param, int error, std::list<sockaddr_storage> addrs) {
    auto id = *std::static_pointer_cast<uint64_t>(param).get();
    if(fdns->statusmap.count(id) == 0){
        return;
    }
    FDnsStatus& status = fdns->statusmap.at(id);
    std::shared_ptr<Dns_Query> que = status.que;
    Dns_Result* rr = nullptr;
    if(error || addrs.empty()){
        rr = new Dns_Result(que->domain);
    }else if(que->type == 1){
        in_addr addr = getInet(que->domain);
        rr = new Dns_Result(que->domain, &addr);
    }else if(opt.ipv6_enabled){
        in6_addr addr = getInet6(que->domain);
        rr = new Dns_Result(que->domain, &addr);
    }else{
        rr = new Dns_Result(que->domain);
    }
    std::shared_ptr<Block> buff = std::make_shared<Block>(BUF_LEN);
    if(error) {
        status.res->send({buff, (size_t)rr->buildError(que.get(), error, (uchar*)buff->data())});
    }else{
        status.res->send({buff, (size_t)rr->build(que.get(), (uchar*)buff->data())});
    }
    status.res->send(nullptr);
}

void FDns::RawCb(std::shared_ptr<void> param, const char* buff, size_t size) {
    auto id = *std::static_pointer_cast<uint64_t>(param).get();
    if(fdns->statusmap.count(id) == 0){
        return;
    }
    FDnsStatus& status = fdns->statusmap[id];
    std::shared_ptr<Dns_Query> que = status.que;
    if(buff){
        LOGD(DDNS, "<FDNS> Query raw response [%d]\n", que->id);
        DNS_HDR *dnshdr = (DNS_HDR*)buff;
        dnshdr->id = htons(que->id);
        status.res->send(buff, size);
    }else {
        LOGD(DDNS, "<FDNS> Query raw response [%d] error\n", que->id);
        Dns_Result rr(que->domain);
        unsigned char sbuff[BUF_LEN];
        status.res->send(sbuff, (size_t)rr.buildError(que.get(), DNS_SERVER_FAIL, sbuff));
    }
    status.res->send(nullptr);
}

void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns: %p\n", this);
    for(const auto& i : statusmap) {
        const FDnsStatus& status = i.second;
        if (status.que == nullptr) {
            dp(param, "  [%" PRIu32 "]: %s, error\n", i.first, status.req->header->geturl().c_str());
            return;
        }
        dp(param, "  [%" PRIu32 "]: %s, %s, id=%d, type=%d\n",
                i.first, status.req->header->geturl().c_str(),
                status.que->domain, status.que->id, status.que->type);
    }
}
