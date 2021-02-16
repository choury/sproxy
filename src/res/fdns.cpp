#include "fdns.h"
#include "prot/dns.h"
#include "prot/resolver.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"
#include "misc/config.h"

#include <inttypes.h>

static Index2<uint32_t, std::string, void*> fdns_records;

static in_addr_t fake_ip = 0 ;

static in_addr getInet(std::string hostname) {
    in_addr addr;

    if(hostname.find_first_of('.') == std::string::npos){
        addr.s_addr = inet_addr(VPNADDR);
    }else if(fdns_records.Get(hostname)){
        addr.s_addr = htonl(fdns_records.Get(hostname)->t1);
    }else{
        fake_ip++;
        addr.s_addr= htonl(fake_ip);
        fdns_records.Add(fake_ip, hostname, nullptr);
    }
    return addr;
}

static in6_addr getInet6(std::string hostname) {
    return mapIpv4(getInet(std::move(hostname)), NAT64PREFIX);
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
    auto record = fdns_records.Get(getFip(&addr));
    if(record){
        return record->t2;
    }else{
        return getaddrstring(&addr);
    }
}

FDns::FDns() {
    if(fake_ip == 0){
        fake_ip = ntohl(inet_addr(VPNADDR));
        fdns_records.Add(fake_ip, "VPN", nullptr);
    }
    rwer = new NullRWer();
}

FDns::~FDns() {
}

void FDns::clean(FDnsStatus* status){
    statusmap.erase(status->que->id);
    delete status->que;
    delete status->resolver;
    delete status;
}

void FDns::request(HttpReq* req, Requester*){
    this->req = req;
    res = new HttpRes(new HttpResHeader(H200));
    req->response(res);
    req->setHandler([this](Channel::signal s){
        if(s == Channel::CHANNEL_SHUTDOWN){
            res->trigger(Channel::CHANNEL_ABORT);
        }
        res = nullptr;
        deleteLater(PEER_LOST_ERR);
    });
    req->attach((Channel::recv_const_t)std::bind(&FDns::Send, this, _1, _2), []{return 512;});
}

void FDns::Send(const void* buff, size_t size) {
    Dns_Query* que = new Dns_Query((const char *)buff, size);
    if(!que->valid){
        char out[size*2];
        for(size_t i = 0; i < size; i++){
            sprintf(out+i*2, "%02X", ((unsigned char*)buff)[i]);
        }
        LOGE("invalid dns request [%zd]: %s\n", size, out);
        delete que;
        return;
    }
    LOGD(DDNS, "FQuery %s [%d]: %d\n", que->domain, que->id, que->type);
    if(statusmap.count(que->id)) {
        //drop dup request
        delete que;
        return;
    }
    FDnsStatus* status = new FDnsStatus{this, que, nullptr};
    statusmap[que->id] = status;
    Dns_Result* result = nullptr;
    if(que->type == 12){
        auto record = fdns_records.Get(getFip(&que->ptr_addr));
        if(record){
            result = new Dns_Result(record->t2.c_str());
        }
    }else if(que->type == 1 || que->type == 28) {
        strategy stra = getstrategy(que->domain);
        if (stra.s == Strategy::direct) {
            status->resolver = query_host(que->domain, DnsCb, (void*)status);
            return;
        }
        if(que->type == 1){
            in_addr addr = getInet(status->que->domain);
            result = new Dns_Result(status->que->domain, &addr);
        }else if(opt.ipv6_enabled) {
            in6_addr addr = getInet6(status->que->domain);
            result = new Dns_Result(status->que->domain, &addr);
        }else{
            result = new Dns_Result(status->que->domain);
        }
    }
    if(result == nullptr) {
        status->resolver = query_dns(status->que->domain, status->que->type, RawCb, (void*)status);
        return;
    }
    unsigned char *const sbuff = (unsigned char *) p_malloc(BUF_LEN);
    res->send(sbuff, result->build(status->que, sbuff));
    clean(status);
}

void FDns::DnsCb(void *param, std::list<sockaddr_storage> addrs) {
    FDnsStatus* status = (FDnsStatus*)param;
    FDns* fdns = status->fdns;
    Dns_Result* rr = nullptr;
    if(addrs.empty()){
        rr = new Dns_Result(status->que->domain);
    }else if(status->que->type == 1){
        in_addr addr = getInet(status->que->domain);
        rr = new Dns_Result(status->que->domain, &addr);
    }else if(opt.ipv6_enabled){
        in6_addr addr = getInet6(status->que->domain);
        rr = new Dns_Result(status->que->domain, &addr);
    }else{
        rr = new Dns_Result(status->que->domain);
    }
    unsigned char *const buff = (unsigned char *) p_malloc(BUF_LEN);
    fdns->res->send(buff, rr->build(status->que, buff));
    fdns->clean(status);
}

void FDns::RawCb(void* param, const char* buff, size_t size) {
    FDnsStatus* status = (FDnsStatus*)param;
    FDns* fdns = status->fdns;
    if(buff){
        LOGD(DDNS, "[FQuery] raw response [%d]\n", status->que->id);
        DNS_HDR *dnshdr = (DNS_HDR*)buff;
        dnshdr->id = htons(status->que->id);
        fdns->res->send(buff, size);
    }else {
        LOGD(DDNS, "[FQuery] raw response [%d] error\n", status->que->id);
        Dns_Result rr(status->que->domain);
        unsigned char *const sbuff = (unsigned char *) p_malloc(BUF_LEN);
        fdns->res->send(sbuff, rr.buildError(status->que, DNS_SERVER_FAIL, sbuff));
    }
    fdns->clean(status);
}

void FDns::deleteLater(uint32_t errcode) {
    for(const auto& i: statusmap){
        delete i.second->que;
        delete i.second->resolver;
        delete i.second;
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
