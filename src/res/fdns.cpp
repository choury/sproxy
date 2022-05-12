#include "fdns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"
#include "misc/config.h"

#include <inttypes.h>

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
    auto fip = getFip(&addr);
    auto record = fdns_records.GetOne(fip);
    if(record != fdns_records.data().end()){
        return record->first.second;
    }
    if(fip > fake_ip && fip < ntohl(inet_addr(VPNEND))) {
        //this is a fake ip, but we has no record, just block it.
        return "fake_ip";
    }
    if(fip == ntohl(inet_addr(VPNADDR))){
        return "VPN";
    }
    return getaddrstring(&addr);
}

FDns::FDns() {
    rwer = std::make_shared<NullRWer>();
}

FDns::~FDns() {
}

void FDns::clean(std::shared_ptr<FDnsStatus> status){
    statusmap.erase(status->que->id);
    delete status->que;
}

void FDns::request(std::shared_ptr<HttpReq> req, Requester*){
    this->req = req;
    res = std::make_shared<HttpRes>(UnpackHttpRes(H200));
    req->response(res);
    req->attach([this](ChannelMessage& msg){
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DDNS, "<FDNS> ignore header for req\n");
            return 1;
        case ChannelMessage::CHANNEL_MSG_DATA:
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            deleteLater(PEER_LOST_ERR);
            return 0;
        }
        return 0;
    }, []{return 512;});
}

void FDns::Recv(Buffer&& bb) {
    Dns_Query* que = new Dns_Query((const char *)bb.data(), bb.len);
    if(!que->valid){
        LOGE("invalid dns request [%zd]\n", bb.len);
        delete que;
        return;
    }
    LOG("[FDNS] Query %s: %d\n", que->domain, que->type);
    if(statusmap.count(que->id)) {
        //drop dup request
        delete que;
        return;
    }
    std::shared_ptr<FDnsStatus> status(new FDnsStatus{this, que});
    statusmap[que->id] = status;
    Dns_Result* result = nullptr;
    if(que->type == 12){
        auto record = fdns_records.GetOne(getFip(&que->ptr_addr));
        if(record != fdns_records.data().end()){
            result = new Dns_Result(record->first.second.c_str());
        }
    }else if(que->type == 1 || que->type == 28) {
        strategy stra = getstrategy(que->domain);
        if (stra.s == Strategy::direct) {
            return query_host(que->domain, DnsCb, status);
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
        return query_dns(que->domain, que->type, RawCb, status);
    }
    auto buff = std::make_shared<Block>(BUF_LEN);
    res->send({buff, (size_t)result->build(que, (uchar*)buff->data())});
    clean(status);
}

void FDns::DnsCb(std::shared_ptr<void> param, int error, std::list<sockaddr_storage> addrs) {
    auto status = std::static_pointer_cast<FDnsStatus>(param);
    Dns_Query* que = status->que;
    FDns* fdns = status->fdns;
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
        fdns->res->send({buff, (size_t)rr->buildError(que, error, (uchar*)buff->data())});
    }else{
        fdns->res->send({buff, (size_t)rr->build(que, (uchar*)buff->data())});
    }
    fdns->clean(status);
}

void FDns::RawCb(std::shared_ptr<void> param, const char* buff, size_t size) {
    auto status = std::static_pointer_cast<FDnsStatus>(param);
    Dns_Query* que = status->que;
    FDns* fdns = status->fdns;
    if(buff){
        LOGD(DDNS, "<FDNS> Query raw response [%d]\n", que->id);
        DNS_HDR *dnshdr = (DNS_HDR*)buff;
        dnshdr->id = htons(que->id);
        fdns->res->send(buff, size);
    }else {
        LOGD(DDNS, "<FDNS> Query raw response [%d] error\n", que->id);
        Dns_Result rr(que->domain);
        unsigned char sbuff[BUF_LEN];
        fdns->res->send(sbuff, (size_t)rr.buildError(que, DNS_SERVER_FAIL, sbuff));
    }
    fdns->clean(status);
}

void FDns::deleteLater(uint32_t errcode) {
    req->detach();
    for(const auto& i: statusmap){
        delete i.second->que;
    }
    statusmap.clear();
    return Server::deleteLater(errcode);
}

void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns %p [%" PRIu32 "]: %s\n", this,
            req->header->request_id,
            req->header->geturl().c_str());
    for(const auto& i: statusmap){
        dp(param, "  %d: %s, type=%d\n",
                i.first, i.second->que->domain, i.second->que->type);
    }
}
